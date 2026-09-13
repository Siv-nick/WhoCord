// src/utils/classify.ts
// ─────────────────────────────────────────────────────────────────────────────
// Frontend mirror of the backend DataProbe classification logic, plus the
// canonical entity → icon name mapping used by the whole UI.

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
  email:               "email",
  hibp:                "breach",
  holehe:              "breach",
  h8mail:              "breach",
  scylla:              "breach",
  gravatar:            "social_profile",
  ghunt:               "social_profile",
  emailrep:            "email",
  connected_account:   "social_profile",
  name_clue:           "name",
  discord_handle:      "username",
  avatar_url:          "image",
  exif_gps:            "location",
  reverse_image:       "image",
  whois:               "domain",
  wayback:             "url",
  ip_address:          "ip",
  ip_geolocation:      "location",
  ssl_certificate:     "domain",
  subdomains:          "domain",
  dns:                 "domain",
  phone_metadata:      "phone",
  phone_carrier:       "phone",
  phoneinfoga:         "phone",
  http_metadata:       "url",
  page_metadata:       "url",
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