# Data handling policy

WhoCord is a local OSINT investigation tool. It runs on the operator's
machine and does not have a server-side component beyond the Flask
process itself. This document describes what data the tool creates,
where it lives, what leaves the machine, and how to remove it.

If you are using WhoCord as part of an engagement — a red-team
assessment, a fraud investigation, a due-diligence review — the
sections below are what you hand to the client or the reviewing party.

---

## 1. What is stored locally

Everything WhoCord produces stays on the local filesystem. There is no
WhoCord-operated server, no telemetry, and no phone-home behaviour of
any kind.

| Location | Contents | Default mode |
|---|---|---|
| `discord_osint/config.json` | Non-sensitive configuration (tool toggles, LLM provider/model, pivot settings, `RETENTION_DAYS`). | `0644` |
| `~/.whocord/session_secret` | Shared-secret token for the local Flask API. | `0600` |
| `~/.whocord/audit_secret` | HMAC key for signing the audit log and evidence manifests. | `0600` |
| `~/.whocord/audit.log` | Append-only, HMAC-signed record of every state-changing action. | `0600` |
| OS keyring | API tokens and secrets (Discord, GitHub, Groq, OpenRouter, HIBP, Apollo, Lusha, Instagram session). | Managed by the OS |
| `investigation_cache/` | Per-investigation artifacts: `report_*.html`, `report_*.md`, `intel_*.json`, `manifest_*.json`. | Inherits the parent directory |
| `investigation_cache/debug_logs/` | Detailed run logs (only when `DEBUG` is on). | `0644` |
| `investigation_cache/avatars/` | Cached avatar images fetched during the run. | `0644` |
| `investigation_cache/socialscan_output/` | Raw socialscan output from prior runs. | `0644` |

Sensitive tokens never live in `config.json`. They are read from and
written to the OS keyring. `config.json` holds the enable flags and the
non-sensitive settings only.

---

## 2. What leaves the machine

WhoCord makes outbound network requests in the course of an
investigation. Each of the following receives data from the machine
when the corresponding feature is enabled. This is the third-party
disclosure surface and it is worth reading carefully.

### 2.1 Target websites

Any URL the investigation discovers may be fetched. The default
behaviour is to fetch:

* profile URLs on platforms the investigation found,
* avatar image URLs,
* JSON API endpoints derived from profile URLs,
* the target URL in the URL module.

These fetches reveal the operator's IP address to the target's hosting
provider. If this matters for a specific engagement, run WhoCord from a
host whose IP is acceptable to disclose, or use a network egress the
client has approved.

### 2.2 LLM providers (Groq, OpenRouter, or any OpenAI-compatible endpoint)

When any AI feature is enabled — persona summary, structured report,
intelligence narrative, canvas chat — WhoCord sends the full
investigation dump to the configured LLM provider. The dump contains
email addresses, social profiles, breach data, identity clues,
extracted EXIF metadata, WHOIS and DNS records, and any other findings
the investigation has produced.

Every LLM call emits a `third_party_contacted` audit event with the
provider name, endpoint, model id, byte counts, and HTTP status. The
event is signed and appears in `~/.whocord/audit.log`.

To disable: leave `ENABLE_AI_REPORT` off, or leave the LLM API key
unset. The chat panel is unavailable without a key.

To run entirely offline: point `LLM_PROVIDER` at a local Ollama
instance once Phase 4's local-model support is enabled. No investigation
data then leaves the machine.

### 2.3 Contact-enrichment providers (Apollo, Lusha)

Both are opt-in and off by default. When enabled, WhoCord submits the
identifiers that passed the trust filter — personal emails and LinkedIn
URLs, primarily — to the provider in exchange for credit consumption.

Every submission emits an `enrichment_complete` finding with the
provider name, number of identifiers submitted, number matched, and
credits consumed. Rejected identifiers are logged in
`intel["enrichment_decisions"]` with the reason for rejection, and
appear in the report's "Rejected identifiers" section.

To disable: leave `ENABLE_APOLLO` / `ENABLE_LUSHA` off, or remove the
corresponding API key.

### 2.4 Public-data lookups

The following are queried as part of a normal investigation and receive
the query value (an email, a username, a domain) but not the
investigation context:

* HaveIBeenPwned (email)
* EmailRep (email)
* Gravatar (email hash)
* DNS resolvers (domain)
* WHOIS servers (domain)
* Archive.org / Wayback Machine (URL)
* SauceNAO (image URL, when `ENABLE_REVERSE_IMG` is on)
* GitHub API (username)
* Discord API (user id, when Discord mode is used)

These are the operators of the respective services. Their privacy
policies apply to the queries WhoCord sends them.

### 2.5 External OSINT tools

Every external tool WhoCord invokes (Holehe, h8mail, GHunt, Blackbird,
GitFive, Maigret, theHarvester, PhoneInfoga, socialscan, ShareTrace,
Scylla) makes its own network requests according to its own privacy
posture. WhoCord does not audit or limit their egress.

---

## 3. Retention

### 3.1 Manual deletion

Every job listed in the History panel can be deleted from the UI. The
delete operation:

1. writes an `investigation_deleted` audit event *before* removing
   anything,
2. overwrites the report, intel snapshot, and manifest with random
   bytes and fsyncs,
3. unlinks those files,
4. removes the in-memory job record.

The audit entry survives. `~/.whocord/audit.log` is not touched by
retention or manual deletion.

### 3.2 Automatic retention

Set `RETENTION_DAYS` in the Config panel to a positive integer (up to
3650) and the background retention pass deletes every non-running job
whose `started_at` is older than that many days. `0` — the default —
disables retention entirely. The pass runs once per day.

Each deletion is audited with a `retention>Nd` reason field so an
auditor can distinguish operator-initiated deletions from automatic
ones.

### 3.3 Secure-delete limitation

`secure_delete()` overwrites file contents with random bytes and
unlinks. This is not a cryptographic guarantee. It does not survive:

* copy-on-write filesystems (btrfs, ZFS, APFS),
* SSD wear levelling,
* filesystem snapshots,
* backups.

Full-disk encryption plus key destruction is the only reliable
mechanism. Treat secure-delete as defence against casual recovery, not
against forensic analysis of the physical disk.

---

## 4. The audit log

`~/.whocord/audit.log` is an append-only, HMAC-signed log. Every entry
is signed and chained to its predecessor, so any modification to an
interior entry breaks the chain from that point forward.

Entries exist for:

* `investigation_started` / `investigation_stopped` / `investigation_finished`
* `third_party_contacted` (LLM calls)
* `report_generated` / `manifest_created`
* `config_changed`
* `investigation_deleted` (operator or retention)
* `retention_pass_completed` / `retention_pass_error`
* `shutdown_requested`

Verify the chain at any time:

    curl -H "X-WhoCord-Token: $(cat ~/.whocord/session_secret)" \
         http://127.0.0.1:5000/api/audit/verify

Or programmatically:

    from discord_osint import audit
    valid, tampered = audit.verify_log()
    print(f"valid={valid} tampered={tampered}")

**Known limitation.** Deletion of the *last* log entry is not
detectable without a published head hash. Any hash chain without an
external anchor has this property. If you need last-entry detection,
periodically record the current head signature somewhere the operator
cannot alter it.

---

## 5. Evidence manifests

Each investigation writes a signed manifest next to its report listing
every artifact's SHA-256 and size, plus a hash of the config the run
operated under. A downstream reviewer can verify:

* the artifacts have not been modified since the manifest was written,
* the manifest itself has not been modified,
* the config the run operated under is the one the operator declares.

The manifest does not prove the investigation actually produced those
artifacts. An operator with filesystem access can write a manifest by
hand. Chain of custody is complete when the reviewer trusts the
operator's machine was not compromised at the time the manifest was
generated.

Verify a manifest:

    from discord_osint import audit, manifest
    m = manifest.load_manifest("investigation_cache/manifest_...json")
    ok, problems = manifest.verify_manifest(m, audit.load_or_create_secret())
    print(ok, problems)

---

## 6. Operator responsibilities

WhoCord is a tool. The operator decides what it investigates and what
happens to its output. Two things are worth stating explicitly:

**Authorisation.** Every jurisdiction has its own rules about what
constitutes lawful OSINT work. The README's disclaimer applies: use
WhoCord only on targets you are authorised to investigate, and only in
ways your jurisdiction permits. The tool does not check authorisation
and will happily run against any input.

**Third-party disclosure.** The operator chooses which LLM provider,
which enrichment provider, and which OSINT tools are enabled. Each
choice sends target data to a third party. For engagements where that
matters, the config panel and the audit log give you the tools to
document exactly what was disclosed to whom.

---

## 7. What WhoCord does not do

* It does not phone home. There is no WhoCord-operated server.
* It does not collect analytics or usage statistics.
* It does not modify the target's systems. Every interaction is a
  read: HTTP GETs, DNS lookups, WHOIS queries, API requests.
* It does not bypass authentication. Features that require a
  logged-in session (Toutatis, some Instagram scraping) require the
  operator to supply a session token and use their own credentials.
* It does not retain anything after a clean uninstall beyond what
  the operator chooses to keep in `investigation_cache/` and
  `~/.whocord/`. Removing those two directories removes everything
  WhoCord created outside the OS keyring.