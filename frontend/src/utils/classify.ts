// src/utils/classify.ts
// ─────────────────────────────────────────────────────────────────────────────
// Frontend mirror of the backend DataProbe classification logic, plus the
// canonical entity → icon name mapping used by the whole UI, plus the
// source → confidence table that powers the node confidence indicator.
//
// Change log
// ----------
// - Added ``sourceConfidence()`` mirroring the backend
//   ``intelligence/extractor.py`` _SOURCE_CONFIDENCE table. Used by
//   GraphNode and InfoCard to derive a per-node confidence when the
//   finding payload does not carry one explicitly.

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
  cordcat_breach:      "breach",

  // ── Social / identity ────────────────────────────────────────────
  gravatar:             "social_profile",
  ghunt:                "social_profile",
  connected_account:    "social_profile",
  social_profiles_found:"social_profile",
  mosint_profiles:      "social_profile",
  cordcat_fivem:        "social_profile",
  cordcat_user:         "username",
  discord_handle:       "username",
  name_clue:            "name",
  name_similarity:      "name",
  confidence_scores:    "unknown",
  activity_profile:     "unknown",
  cordcat_dsa_statement:"unknown",
  cordcat_score:        "unknown",

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

// ─── Source → confidence ─────────────────────────────────────────────
// Mirrors discord_osint/intelligence/extractor.py::_SOURCE_CONFIDENCE.
// Used when a finding payload does not carry an explicit confidence
// field. The values are the same the backend uses when building the
// intelligence graph, so a node's confidence here matches the entity
// confidence there for the same source string.
const SOURCE_CONFIDENCE: Record<string, number> = {
  manual_input:         0.92,
  discord_api:          0.88,
  discord_enrich:       0.82,
  snowflake:            0.82,
  gitfive:              0.72,
  scrape_github:        0.72,
  smtp_verify:          0.70,
  ghunt:                0.68,
  cord_cat:             0.66,
  hibp:                 0.65,
  h8mail:               0.65,
  holehe:               0.65,
  emailrep:             0.62,
  discord_bio:          0.60,
  scrape_twitter:       0.60,
  scrape_reddit:        0.58,
  scrape_:              0.55,
  gravatar:             0.55,
  "socid-extractor":    0.52,
  wayback:              0.50,
  activity_inference:   0.50,
  nametrace:            0.48,
  whois:                0.47,
  location_inference:   0.44,
  langdetect:           0.44,
  naminter:             0.40,
  generic_scrape:       0.36,
  api_fetch:            0.44,
  crtsh:                0.60,
  avatar_collection:    0.70,
};

const DEFAULT_CONFIDENCE = 0.38;

/**
 * Return the confidence for a finding source string, or undefined when
 * the source is empty. Mirrors the backend's longest-prefix lookup so
 * "scrape_github" and "scrape_twitter" both resolve to their specific
 * values rather than the shorter "scrape_" prefix.
 */
export function sourceConfidence(source: string | undefined | null): number | undefined {
  if (!source) return undefined;
  const s = String(source).toLowerCase();
  if (s in SOURCE_CONFIDENCE) return SOURCE_CONFIDENCE[s];

  let bestKey = "";
  let bestVal = DEFAULT_CONFIDENCE;
  for (const [key, val] of Object.entries(SOURCE_CONFIDENCE)) {
    if (s.startsWith(key) && key.length > bestKey.length) {
      bestKey = key;
      bestVal = val;
    }
  }
  return bestVal;
}

/**
 * Coerce a raw finding payload into a confidence value. Prefers an
 * explicit ``confidence`` field if the payload carries one, otherwise
 * derives from ``source``. Returns undefined when neither is available.
 */
export function confidenceForFinding(
  payload: Record<string, unknown>,
): number | undefined {
  const explicit = payload["confidence"];
  if (typeof explicit === "number" && explicit >= 0 && explicit <= 1) {
    return explicit;
  }
  const source = payload["source"];
  if (typeof source === "string") {
    return sourceConfidence(source);
  }
  return undefined;
}