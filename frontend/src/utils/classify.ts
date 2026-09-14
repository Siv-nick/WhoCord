// src/utils/classify.ts
// ─────────────────────────────────────────────────────────────────────────────
// Frontend mirror of the backend DataProbe classification logic, plus the
// canonical entity → icon name mapping used by the whole UI.
//
// Change log
// ----------
// - `findingTypeToEntityType` map brought up to date with every finding
//   type the backend emits. `hibp_skipped` and `intelligence_narrative`
//   were previously falling through to "unknown", which made the
//   "HIBP could not check" case visually indistinguishable from an
//   unrecognised tool output.
// - Added module-level documentation of which backend module emits each
//   finding type so the map stays in sync when new stages are added.

import type { IconName } from "../components/Icons";
import type { NodeEntityType, NodeModule } from "../types/graph";

// ─── Patterns (mirror discord_osint/pipeline/stages/data_probe.py) ───
const EMAIL_RE  = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
const PHONE_RE  = /^(\+\d[\d\s\-().]{5,14}|\d{8,15})$/;
const DOMAIN_RE = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/;

// ─── Public classification ───────────────────────────────────────────
export type ClassifyResult = {
  module:     NodeModule;
  entityType: NodeEntityType;
};

export function classifyInput(raw: string): ClassifyResult {
  const s = raw.trim();

  if (s.startsWith("http://") || s.startsWith("https://")) {
    return { module: "url", entityType: "url" };
  }

  if (EMAIL_RE.test(s)) {
    return { module: "email", entityType: "email" };
  }

  const stripped = s.replace(/[\s\-().]/g, "");
  if (PHONE_RE.test(stripped) || (s.startsWith("+") && stripped.length >= 7)) {
    return { module: "phone", entityType: "phone" };
  }

  if (s.includes(".") && !s.includes(" ") && s.length >= 4 && DOMAIN_RE.test(s)) {
    return { module: "domain", entityType: "domain" };
  }

  return { module: "manual", entityType: "username" };
}

// ─── Finding type → entity type ──────────────────────────────────────
//
// Backend sources, kept as a comment so this table is easy to audit when
// a stage gains a new finding type:
//
//   email_investigation.py / email_intel.py:
//     email, holehe, h8mail, hibp, hibp_skipped, emailrep, ghunt,
//     gravatar, scylla
//   discord_mode.py:
//     discord_handle, avatar_url, connected_account, name_clue
//   scraping_stage.py / media.py:
//     avatar_downloaded, exif_gps, exif_date, exif_camera,
//     exif_metadata, reverse_image, perceptual_hash, image_info, ocr_text
//   analysis.py / extras.py:
//     whois, wayback, name_similarity, confidence_scores, location,
//     language
//   domain_investigation.py:
//     dns, ip_address, ip_geolocation, ssl_certificate, subdomains,
//     harvester_emails, harvester_hosts
//   url_analysis.py:
//     http_metadata, page_metadata, emails_on_page, interesting_links,
//     url_domain, safe_browsing
//   phone_investigation.py:
//     phone_metadata, phone_carrier, phoneinfoga
//   intelligence/engine.py:
//     correlations, intelligence_report, intelligence_narrative,
//     persona_summary
//   username_search / mosint:
//     mosint_profiles, social_profiles_found
//   pivot.py (status — handled as separate events, not `finding`):
//     pivot_start, pivot_done, pivot_error, pivot_skipped
//
const FINDING_TO_ENTITY: Record<string, NodeEntityType> = {
  // ── Email ────────────────────────────────────────────────────────
  email:               "email",
  emailrep:            "email",

  // ── Breach ───────────────────────────────────────────────────────
  hibp:                "breach",
  hibp_skipped:        "breach",
  holehe:              "breach",
  h8mail:              "breach",
  scylla:              "breach",

  // ── Social / identity ────────────────────────────────────────────
  gravatar:            "social_profile",
  ghunt:               "social_profile",
  connected_account:   "social_profile",
  social_profiles_found:"social_profile",
  mosint_profiles:     "social_profile",
  discord_handle:      "username",
  name_clue:           "name",
  name_similarity:     "name",
  confidence_scores:   "unknown",

  // ── Media ────────────────────────────────────────────────────────
  avatar_url:          "image",
  avatar_downloaded:   "image",
  reverse_image:       "image",
  perceptual_hash:     "image",
  image_info:          "image",
  ocr_text:            "image",

  // ── Location ─────────────────────────────────────────────────────
  exif_gps:            "location",
  ip_geolocation:      "location",
  location:            "location",

  // ── Network / domain ─────────────────────────────────────────────
  whois:               "domain",
  dns:                 "domain",
  ssl_certificate:     "domain",
  subdomains:          "domain",
  ip_address:          "ip",

  // ── URL ──────────────────────────────────────────────────────────
  wayback:             "url",
  http_metadata:       "url",
  page_metadata:       "url",
  emails_on_page:      "url",
  interesting_links:   "url",
  url_domain:          "domain",
  safe_browsing:       "url",

  // ── Phone ────────────────────────────────────────────────────────
  phone_metadata:      "phone",
  phone_carrier:       "phone",
  phoneinfoga:         "phone",

  // ── Email harvesting ─────────────────────────────────────────────
  harvester_emails:    "email",
  harvester_hosts:     "domain",

  // ── Intelligence ─────────────────────────────────────────────────
  correlations:        "unknown",
  intelligence_report: "unknown",
  intelligence_narrative: "unknown",
  persona_summary:     "unknown",

  // ── Probe ────────────────────────────────────────────────────────
  probe_classification:"unknown",
};

export function findingTypeToEntityType(findingType: string): NodeEntityType {
  return FINDING_TO_ENTITY[findingType] ?? "unknown";
}

// ─── Entity type → icon name ─────────────────────────────────────────
const ENTITY_ICONS: Record<NodeEntityType, IconName> = {
  email:          "mail",
  username:       "atSign",
  social_profile: "users",
  phone:          "phone",
  domain:         "globe",
  url:            "link",
  image:          "image",
  breach:         "alert",
  ip:             "server",
  name:           "user",
  location:       "mapPin",
  unknown:        "dot",
};

export function entityIconName(type: NodeEntityType): IconName {
  return ENTITY_ICONS[type] ?? "dot";
}

// ─── Module → display label ──────────────────────────────────────────
export const MODULE_LABELS: Record<NodeModule, string> = {
  manual:  "Username",
  discord: "Discord",
  email:   "Email",
  domain:  "Domain",
  phone:   "Phone",
  image:   "Image",
  url:     "URL",
  probe:   "Probe",
  root:    "Root",
};

// ─── Module → icon name ──────────────────────────────────────────────
export const MODULE_ICONS: Record<NodeModule, IconName> = {
  manual:  "atSign",
  discord: "message",
  email:   "mail",
  domain:  "globe",
  phone:   "phone",
  image:   "image",
  url:     "link",
  probe:   "search",
  root:    "target",
};