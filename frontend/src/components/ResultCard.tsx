// src/components/ResultCard.tsx
import React from "react";
import type { Finding, FindingCategory } from "../types/investigation";
import { Icon, type IconName } from "./Icons";

// ─── Category styling ────────────────────────────────────────────────
const CATEGORY_STYLES: Record<
  FindingCategory,
  { border: string; badge: string; icon: IconName }
> = {
  identity:     { border: "border-violet-700/50",  badge: "bg-violet-500/15 text-violet-300",  icon: "user" },
  email:        { border: "border-sky-700/50",     badge: "bg-sky-500/15 text-sky-300",        icon: "mail" },
  social:       { border: "border-purple-700/50",  badge: "bg-purple-500/15 text-purple-300",  icon: "users" },
  breach:       { border: "border-rose-700/50",    badge: "bg-rose-500/15 text-rose-300",      icon: "alert" },
  media:        { border: "border-amber-700/50",   badge: "bg-amber-500/15 text-amber-300",    icon: "image" },
  intelligence: { border: "border-emerald-700/50", badge: "bg-emerald-500/15 text-emerald-300", icon: "brain" },
  pivot:        { border: "border-emerald-700/50", badge: "bg-emerald-500/15 text-emerald-300", icon: "refresh" },
  phone:        { border: "border-edge-1",         badge: "bg-white/[.04] text-zinc-400",      icon: "phone" },
  url:          { border: "border-edge-1",         badge: "bg-white/[.04] text-zinc-400",      icon: "link" },
  probe:        { border: "border-edge-1",         badge: "bg-white/[.04] text-zinc-400",      icon: "search" },
  network:      { border: "border-edge-1",         badge: "bg-white/[.04] text-zinc-400",      icon: "globe" },
  other:        { border: "border-edge-1",         badge: "bg-white/[.04] text-zinc-400",      icon: "dot" },
};

const TYPE_LABELS: Record<string, string> = {
  email:               "Email address",
  name_clue:           "Name clue",
  avatar_url:          "Avatar URL",
  connected_account:   "Connected account",
  discord_handle:      "Discord handle",
  holehe:              "Site registrations",
  hibp:                "HIBP breaches",
  h8mail:              "Breach data",
  gravatar:            "Gravatar profile",
  ghunt:               "Google account",
  emailrep:            "EmailRep score",
  exif_gps:            "EXIF GPS",
  reverse_image:       "Reverse image match",
  correlations:        "Correlations",
  intelligence_report: "Intelligence report",
  persona_summary:     "AI persona summary",
  wayback:             "Wayback snapshot",
  whois:               "WHOIS data",
  name_similarity:     "Name similarity",
  confidence_scores:   "Identity confidence",
  avatar_downloaded:   "Avatar downloaded",
  language:            "Language detected",
  location:            "Location inferred",
};

function buildDetail(finding: Finding): string {
  const p = finding.payload;
  if (p.value) return String(p.value);
  if (p.email) return String(p.email);
  if (p.url)   return String(p.url);
  if (p.domain) return String(p.domain);
  if (p.platform) return `${p.platform}${p.value ? `: ${p.value}` : ""}`;
  if (p.sites)
    return `${(p.sites as string[]).slice(0, 4).join(", ")}${
      (p.sites as string[]).length > 4 ? "…" : ""
    }`;
  if (p.breaches !== undefined) return `${p.breaches} breach(es)`;
  if (p.entity_count !== undefined)
    return `${p.entity_count} entities, ${p.correlation_count} correlations`;
  return "";
}

interface Props {
  finding: Finding;
}

export default function ResultCard({ finding }: Props) {
  const styles = CATEGORY_STYLES[finding.category];
  const detail = buildDetail(finding);

  return (
    <div
      className={`rounded-lg border ${styles.border} bg-ink-850/70
                  p-3 flex gap-3 items-start anim-rise`}
    >
      <span className="mt-0.5 shrink-0 text-zinc-300">
        <Icon name={styles.icon} size={16} />
      </span>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap mb-1">
          <span
            className={`text-[10px] font-bold px-1.5 py-0.5 rounded
                        uppercase tracking-wider ${styles.badge}`}
          >
            {TYPE_LABELS[finding.type] ?? finding.type}
          </span>
          <span className="text-[10px] text-zinc-600">{finding.stage}</span>
        </div>

        {detail && (
          <p className="text-[13px] text-zinc-300 break-all">{detail}</p>
        )}

        {finding.payload.source && (
          <p className="text-[10px] text-zinc-600 mt-0.5">
            via {String(finding.payload.source)}
          </p>
        )}
      </div>

      <span className="text-[10px] text-zinc-700 shrink-0 tabular-nums">
        {new Date(finding.timestamp).toLocaleTimeString()}
      </span>
    </div>
  );
}