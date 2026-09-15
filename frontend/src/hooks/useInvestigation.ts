// src/hooks/useInvestigation.ts
//
// Streams the /run SSE response over a POST fetch.
//
// EventSource cannot set custom headers, so it was replaced with
// fetch + ReadableStream — the same pattern useChat.ts already uses.
//
// Change log
// ----------
// - Phase 4: derives a confidence value for each created node from
//   the finding payload (via classify.confidenceForFinding) and
//   stores it on the GraphNode. The canvas renders this as a thin
//   ring around the node and the InfoCard shows it explicitly.
// - Pre-existing bug fixed: the finding handler used to read
//   currentStage from a stale closure captured at start() time, so
//   every Finding was recorded with stage="". Now read through a ref.

import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch, runUrl, stopInvestigation } from "../utils/api";
import {
  classifyInput,
  confidenceForFinding,
  findingTypeToEntityType,
} from "../utils/classify";
import { childPosition } from "../utils/graphLayout";
import { newEdgeId, newNodeId, useGraphState } from "./useGraphState";
import type {
  GraphEdge,
  GraphNode,
  InfoField,
  NodeEntityType,
} from "../types/graph";
import type {
  Finding,
  FindingCategory,
  FindingPayload,
  PivotInfo,
  PivotStatus,
  RunParams,
} from "../types/investigation";

const STAGE_ORDER = [
  "discord_mode", "discovery", "scraping", "media",
  "analysis", "intelligence", "email_intel", "reporting",
];

function stageProgress(name: string, done: boolean): number {
  const idx = STAGE_ORDER.indexOf(name);
  if (idx === -1) return 0;
  const base = Math.round((idx / STAGE_ORDER.length) * 95);
  return done ? Math.round(((idx + 1) / STAGE_ORDER.length) * 95) : base;
}

const NOISY_URL_FRAGMENTS = [
  "/api/", "/oembed", "?validate=", "/signup/", "checkusername",
  "email_available", "/wayback/available", "/graphql/", "username_available",
  "showAuthorExists", "/rest/u/", "/public/users", "/public/v1/",
  "/v1.1/sites/", "/v2/orgs/", "/v2/users/", "/v1/users/",
  "/v1.3/users/", "/v3/users/", "/v4/users", "/v6/user/",
  "/account/v1/accounts/",
];

function isNoisyUrl(url: string): boolean {
  if (!url) return false;
  const u = url.toLowerCase();
  return NOISY_URL_FRAGMENTS.some(frag => u.includes(frag));
}

const AVATAR_CDN_PATTERNS = [
  /avatars\.githubusercontent\.com/,
  /cdn\.discordapp\.com\/avatars/,
  /pbs\.twimg\.com\/profile_images/,
  /lh\d+\.googleusercontent\.com/,
  /graph\.facebook\.com.*picture/,
  /gravatar\.com\/avatar/,
  /secure\.gravatar\.com\/avatar/,
  /media\.licdn\.com.*profile/,
  /yt\d+\.googleusercontent\.com/,
  /steamcdn-a\.akamaihd\.net.*avatars/,
  /i\.imgur\.com/,
  /unavatar\.io/,
];

function isAvatarUrl(url: string): boolean {
  if (!url || !url.startsWith("http")) return false;
  if (/\.(png|jpg|jpeg|gif|webp|svg)(\?|$)/i.test(url)) return true;
  return AVATAR_CDN_PATTERNS.some(re => re.test(url));
}

function nodeKey(ftype: string, p: Record<string, unknown>): string {
  switch (ftype) {
    case "api_response":
    case "profile_url":
    case "avatar_url":
      return `url:${String(p.url ?? p.value ?? "").toLowerCase()}`;
    case "email":
    case "holehe":
    case "hibp":
    case "hibp_skipped":
    case "h8mail":
    case "gravatar":
    case "ghunt":
    case "emailrep":
    case "scylla":
      return `email:${String(p.email ?? p.value ?? "").toLowerCase()}`;
    case "name_clue":
      return `name:${String(p.value ?? "").toLowerCase()}`;
    case "connected_account":
      return `acct:${String(p.platform ?? "").toLowerCase()}:${String(p.value ?? "").toLowerCase()}`;
    case "exif_gps":
      return `gps:${String(p.file ?? "")}`;
    case "reverse_image":
      return `rimg:${String(p.file ?? "")}`;
    case "whois":
      return `whois:${String(p.domain ?? "").toLowerCase()}`;
    case "wayback":
      return `wb:${String(p.url ?? "").toLowerCase()}`;
    case "language":
      return `lang:${String(p.value ?? "").toLowerCase()}`;
    case "location":
      return `loc:${String(p.value ?? "").toLowerCase()}`;
    default:
      return `${ftype}:${String(
        p.value ?? p.url ?? p.email ?? p.domain ?? p.file ?? "",
      ).toLowerCase()}`;
  }
}

function extractLabel(ftype: string, p: Record<string, unknown>): string {
  switch (ftype) {
    case "profile_url":
      return String(p.site ?? p.url ?? ftype).slice(0, 60);
    case "email":
      return String(p.value ?? p.email ?? "").slice(0, 60);
    case "ghunt":
      return `GHunt: ${String(p.email ?? "")}`.slice(0, 60);
    case "holehe":
      return `Holehe: ${String(p.email ?? "")}`.slice(0, 60);
    case "hibp":
      return `HIBP: ${String(p.email ?? "")}`.slice(0, 60);
    case "hibp_skipped":
      return `HIBP skipped: ${String(p.email ?? "")}`.slice(0, 60);
    case "h8mail":
      return `h8mail: ${String(p.email ?? "")}`.slice(0, 60);
    case "gravatar":
      return `Gravatar: ${String(p.email ?? "")}`.slice(0, 60);
    case "name_clue":
      return String(p.value ?? "").slice(0, 60);
    case "cordcat_user":
      return `CordCat: ${String(p.username ?? "")}`.slice(0, 60);
    case "cordcat_breach":
      return `CordCat breach: ${String(p.count ?? "?")}`;
    case "cordcat_fivem":
      return `CordCat FiveM: ${String(p.count ?? "?")}`;
    case "cordcat_dsa_statement":
      return `DSA: ${String(p.facts ?? "").slice(0, 50)}`;
    case "cordcat_score":
      return `CordCat score: ${String(p.value ?? "?")}`;
    case "activity_profile":
      return `Activity: ${String(p.offset ?? "?")}`;
    default:
      return (
        String(p.value  ?? "") ||
        String(p.email  ?? "") ||
        String(p.url    ?? "") ||
        String(p.domain ?? "") ||
        (Array.isArray(p.sites) ? (p.sites as string[]).slice(0, 2).join(", ") : "") ||
        ftype
      ).slice(0, 60);
  }
}

function buildInfoFields(ftype: string, p: Record<string, unknown>): InfoField[] {
  const fields: InfoField[] = [];
  const push = (key: string, label: string, value: string, opts: Partial<InfoField> = {}) => {
    if (value) fields.push({ key, label, value, editable: false, ...opts });
  };

  push("source", "Source", String(p.source ?? ""));

  switch (ftype) {
    case "profile_url": {
      const url  = String(p.url ?? "");
      const site = String(p.site ?? "");
      push("site", "Platform", site);
      push("url", "URL", url, { isLink: true });
      break;
    }
    case "api_response": {
      const url = String(p.url ?? "");
      const kf  = p.key_fields;

      if (Array.isArray(kf) && kf.length > 0) {
        fields.push({
          key: "endpoint",
          label: "Endpoint",
          value: url,
          editable: false,
          isLink: true,
        });
        (kf as Array<{ label: string; value: string }>).forEach((f, i) => {
          if (f && f.label && f.value) {
            fields.push({
              key: `kf_${i}`,
              label: f.label,
              value: String(f.value),
              editable: false,
            });
          }
        });
        return fields;
      }

      const data = p.data as Record<string, unknown> | unknown[] | undefined;
      push("api_url", "API URL", url, { isLink: true });

      if (data && typeof data === "object" && !Array.isArray(data)) {
        for (const [k, v] of Object.entries(data as Record<string, unknown>)) {
          if (v === null || v === undefined) continue;
          if (typeof v === "object") continue;
          push(k, k.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
               String(v).slice(0, 200));
        }
      }
      break;
    }
    case "ghunt": {
      push("email", "Email", String(p.email ?? ""));
      const pic = String(p.profile_picture ?? p.photo_url ?? p.picture ?? "");
      if (pic) fields.push({ key: "avatar", label: "Photo", value: pic, editable: false, isImage: true });
      push("name", "Name", String(p.name ?? p.display_name ?? ""));
      push("gaia_id", "Gaia ID", String(p.gaia_id ?? ""));
      push("last_profile_edit", "Last Edited", String(p.last_profile_edit ?? ""));
      push("profile_url", "Profile URL", String(p.profile_url ?? ""), { isLink: true });
      const services = p.activated_services;
      if (Array.isArray(services) && services.length) {
        push("services", "Services", (services as string[]).join(", "));
      } else if (typeof services === "string" && services) {
        push("services", "Services", services);
      }
      const handled = new Set(["email","profile_picture","photo_url","picture","name",
        "display_name","gaia_id","last_profile_edit","profile_url",
        "activated_services","source","type"]);
      for (const [k, v] of Object.entries(p)) {
        if (!handled.has(k) && v && typeof v !== "object") {
          push(k, k.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()), String(v));
        }
      }
      break;
    }
    case "holehe": {
      push("email", "Email", String(p.email ?? ""));
      if (Array.isArray(p.sites)) {
        push("registered_on", "Registered On", (p.sites as string[]).join(", "));
        push("count", "Site Count", String((p.sites as string[]).length));
      }
      break;
    }
    case "hibp": {
      push("email", "Email", String(p.email ?? ""));
      push("breaches", "Breaches", `${String(p.breaches ?? "0")} breach(es)`);
      if (Array.isArray(p.breach_names)) {
        push("breach_names", "Breach Names", (p.breach_names as string[]).join(", "));
      }
      break;
    }
    case "hibp_skipped": {
      push("email", "Email", String(p.email ?? ""));
      push("reason", "Reason", String(p.reason ?? "check could not be performed"));
      break;
    }
    case "h8mail": {
      push("email", "Email", String(p.email ?? ""));
      const result = p.result;
      if (result && typeof result === "object") {
        const r = result as Record<string, unknown>;
        push("status", "Status", String(r.status ?? ""));
        push("password", "Password", String(r.password ?? ""));
        push("source", "Source", String(r.source ?? ""));
        if (Array.isArray(r.emails)) {
          push("linked_emails", "Linked Emails", (r.emails as string[]).join(", "));
        }
      } else if (typeof result === "string") {
        push("result", "Result", result);
      }
      break;
    }
    case "gravatar": {
      push("email", "Email", String(p.email ?? ""));
      const url = String(p.url ?? "");
      if (url) {
        if (isAvatarUrl(url)) {
          fields.push({ key: "avatar", label: "Avatar", value: url, editable: false, isImage: true });
        } else {
          push("url", "URL", url, { isLink: true });
        }
      }
      break;
    }
    case "email": {
      push("email", "Email", String(p.value ?? p.email ?? ""));
      push("source_tool", "Found by", String(p.source ?? ""));
      break;
    }
    case "name_clue": {
      push("name", "Name", String(p.value ?? ""));
      push("source_tool", "Found by", String(p.source ?? ""));
      break;
    }
    case "avatar_url": {
      const url = String(p.value ?? p.url ?? "");
      if (url) {
        fields.push({ key: "avatar", label: "Avatar", value: url, editable: false, isImage: true });
      }
      break;
    }
    case "cordcat_user": {
      push("username", "Username", String(p.username ?? ""));
      push("display_name", "Display Name", String(p.display_name ?? ""));
      push("account_created", "Account Created", String(p.account_created ?? ""));
      const badges = p.badges;
      if (Array.isArray(badges) && badges.length) {
        push("badges", "Badges", (badges as string[]).join(", "));
      }
      const avatar = String(p.avatar ?? "");
      if (avatar && isAvatarUrl(avatar)) {
        fields.push({ key: "avatar", label: "Avatar", value: avatar, editable: false, isImage: true });
      }
      break;
    }
    case "cordcat_breach": {
      push("count", "Entries", String(p.count ?? ""));
      const datasets = p.datasets;
      if (Array.isArray(datasets) && datasets.length) {
        push("datasets", "Datasets", (datasets as string[]).join(", "));
      }
      const exposed = p.exposed_fields;
      if (Array.isArray(exposed) && exposed.length) {
        push("exposed_fields", "Exposed Fields", (exposed as string[]).join(", "));
      }
      if (p.geo && typeof p.geo === "object") {
        const g = p.geo as Record<string, unknown>;
        const parts = Object.entries(g).map(([k, v]) => `${k}: ${v}`);
        if (parts.length) push("geo", "GeoIP", parts.join(", "));
      }
      if (p.asn && typeof p.asn === "object") {
        const a = p.asn as Record<string, unknown>;
        const parts = Object.entries(a).map(([k, v]) => `${k}: ${v}`);
        if (parts.length) push("asn", "ASN", parts.join(", "));
      }
      break;
    }
    case "cordcat_fivem": {
      push("count", "Records", String(p.count ?? ""));
      const records = p.records;
      if (Array.isArray(records) && records.length) {
        const first = records[0];
        if (first && typeof first === "object") {
          for (const [k, v] of Object.entries(first as Record<string, unknown>)) {
            if (v && typeof v !== "object") push(k, k, String(v));
          }
        }
      }
      break;
    }
    case "cordcat_dsa_statement": {
      push("facts", "Facts", String(p.facts ?? ""));
      push("scope", "Scope", String(p.scope ?? ""));
      push("grounds", "Legal Grounds", String(p.grounds ?? ""));
      break;
    }
    case "cordcat_score": {
      push("value", "Score", String(p.value ?? ""));
      const reasons = p.reasons;
      if (Array.isArray(reasons) && reasons.length) {
        push("reasons", "Reasons", (reasons as string[]).join(", "));
      }
      break;
    }
    case "activity_profile": {
      push("offset", "Inferred Timezone", String(p.offset ?? ""));
      push("active", "Active Hours", String(p.active ?? ""));
      push("cadence", "Posting Cadence", String(p.cadence ?? ""));
      push("confidence", "Confidence", String(p.confidence ?? ""));
      push("sample", "Sample Size", String(p.sample ?? ""));
      break;
    }
    default: {
      const url = String(p.url ?? "");
      const val = String(p.value ?? "");
      if (url) push("url", "URL", url, { isLink: true });
      if (val && val !== url) push("value", "Value", val, { editable: true });
      if (p.domain) push("domain", "Domain", String(p.domain));
      if (p.platform) push("platform", "Platform", String(p.platform));
      if (Array.isArray(p.sites)) {
        push("sites", "Sites", (p.sites as string[]).slice(0, 10).join(", "));
      }
      const knownKeys = new Set(["url", "value", "domain", "platform", "sites", "source", "type"]);
      for (const [k, v] of Object.entries(p)) {
        if (!knownKeys.has(k) && v && typeof v !== "object" && String(v).trim()) {
          push(k, k.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()), String(v).slice(0, 120));
        }
      }
      break;
    }
  }
  return fields;
}

const SKIP_TYPES = new Set([
  "avatar_downloaded", "probe_classification", "intelligence_report",
  "persona_summary", "social_profiles_found", "stage_start", "stage_done",
]);

const FINDING_CATEGORIES: Record<string, FindingCategory> = {
  email:               "email",
  name_clue:           "identity",
  discord_handle:      "identity",
  avatar_url:          "media",
  avatar_downloaded:   "media",
  connected_account:   "social",
  holehe:              "breach",
  hibp:                "breach",
  hibp_skipped:        "breach",
  h8mail:              "breach",
  scylla:              "breach",
  gravatar:            "social",
  ghunt:               "identity",
  emailrep:            "email",
  exif_gps:            "media",
  reverse_image:       "media",
  correlations:        "intelligence",
  intelligence_report: "intelligence",
  persona_summary:     "intelligence",
  wayback:             "social",
  whois:               "social",
  pivot_start:         "pivot",
  pivot_done:          "pivot",
  pivot_error:         "pivot",
  pivot_skipped:       "pivot",
  cordcat_user:        "identity",
  cordcat_breach:      "breach",
  cordcat_fivem:       "identity",
  cordcat_dsa_statement: "identity",
  cordcat_score:       "intelligence",
  activity_profile:    "intelligence",
};

let _fid = 0;
const nextFindingId = () => `f_${++_fid}_${Date.now()}`;

export type InvestigationStatus = "idle" | "running" | "stopping" | "done" | "cancelled" | "error";

export interface UseInvestigationResult {
  progress:     number;
  running:      boolean;
  stopping:     boolean;
  jobId:        string | null;
  reportUrl:    string | null;
  logs:         string[];
  currentStage: string | null;
  status:       InvestigationStatus;
  target:       string;
  mode:         string;
  pivotDepth:   number;
  pivots:       PivotInfo[];
  findings:     Finding[];
  start:        (parentNodeId: string, params: RunParams) => void;
  stop:         () => Promise<void>;
  resetParentCounter: (parentNodeId: string) => void;
}

export function useInvestigation(): UseInvestigationResult {
  const { addNode, addEdge, updateNode } = useGraphState();

  const abortRef        = useRef<AbortController | null>(null);
  const urlToNodeId     = useRef<Map<string, string>>(new Map());
  const parentNextIndex = useRef<Map<string, number>>(new Map());
  const parentNodeKeys  = useRef<Map<string, Set<string>>>(new Map());
  const jobIdRef        = useRef<string | null>(null);
  const parentRef       = useRef<string | null>(null);

  const [progress,     setProgress]     = useState(0);
  const [running,      setRunning]      = useState(false);
  const [stopping,     setStopping]     = useState(false);
  const [jobId,        setJobId]        = useState<string | null>(null);
  const [reportUrl,    setReportUrl]    = useState<string | null>(null);
  const [logs,         setLogs]         = useState<string[]>([]);
  const [currentStage, setCurrentStage] = useState<string | null>(null);

  const [status,     setStatus]     = useState<InvestigationStatus>("idle");
  const [target,     setTarget]     = useState<string>("");
  const [mode,       setMode]       = useState<string>("");
  const [pivotDepth, setPivotDepth] = useState<number>(0);
  const [pivots,     setPivots]     = useState<PivotInfo[]>([]);
  const [findings,   setFindings]   = useState<Finding[]>([]);

  // Live currentStage for the finding handler.
  const currentStageRef = useRef<string | null>(null);
  currentStageRef.current = currentStage;

  const closeStream = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
  }, []);

  useEffect(() => {
    return () => {
      abortRef.current?.abort();
      abortRef.current = null;
    };
  }, []);

  const stop = useCallback(async () => {
    if (!running && status !== "running") return;
    setStopping(true);
    setStatus("stopping");

    const result = await stopInvestigation(jobIdRef.current ?? undefined);
    if (!result.success) {
      console.warn("stopInvestigation failed:", result.error);
      setStopping(false);
      if (result.error && !result.error.includes("not running")) {
        setStatus("running");
      }
    }
  }, [running, status]);

  const resetParentCounter = useCallback((parentNodeId: string) => {
    parentNextIndex.current.set(parentNodeId, 0);
    parentNodeKeys.current.delete(parentNodeId);
  }, []);

  const shouldSkipAsDuplicate = useCallback(
    (parentNodeId: string, ftype: string, p: Record<string, unknown>): boolean => {
      const key = nodeKey(ftype, p);
      let keys = parentNodeKeys.current.get(parentNodeId);
      if (!keys) {
        keys = new Set<string>();
        parentNodeKeys.current.set(parentNodeId, keys);
      }
      if (keys.has(key)) return true;
      keys.add(key);
      return false;
    },
    [],
  );

  const start = useCallback((parentNodeId: string, params: RunParams) => {
    abortRef.current?.abort();

    urlToNodeId.current = new Map();
    parentNodeKeys.current.set(parentNodeId, new Set<string>());
    parentRef.current = parentNodeId;

    const liveState = useGraphState.getState();
    const liveNodes = liveState.nodes;
    const liveEdges = liveState.edges;

    const existingChildCount = liveEdges.filter(e => e.sourceId === parentNodeId).length;
    const trackedIndex = parentNextIndex.current.get(parentNodeId) ?? 0;
    const startIndex = Math.max(trackedIndex, existingChildCount);

    jobIdRef.current = null;

    setProgress(0);
    setRunning(true);
    setStopping(false);
    setJobId(null);
    setReportUrl(null);
    setLogs([]);
    setCurrentStage(null);
    setStatus("running");
    setTarget(params.username || params.email || params.user_id || params.target || "");
    setMode(params.mode);
    setPivotDepth(0);
    setPivots([]);
    setFindings([]);

    updateNode(parentNodeId, { investigating: true, progress: 0 });

    const parentNode = liveNodes.find(n => n.id === parentNodeId);
    const parentPos  = parentNode?.position ?? { x: 0, y: 0 };

    let currentIndex = startIndex;

    const controller = new AbortController();
    abortRef.current = controller;

    const handleEvent = (parsed: { type: string; payload: Record<string, unknown> }) => {
      const { type: evtType, payload: p } = parsed;

      switch (evtType) {
        case "job_start":
          jobIdRef.current = String(p.job_id ?? "") || null;
          setJobId(jobIdRef.current);
          if (p.target) setTarget(String(p.target));
          if (p.mode)   setMode(String(p.mode));
          break;

        case "stage_start": {
          const name = String(p.stage ?? "");
          setCurrentStage(name);
          const prog = stageProgress(name, false);
          setProgress(prog);
          updateNode(parentNodeId, { progress: prog });
          break;
        }

        case "stage_done": {
          const prog = stageProgress(String(p.stage ?? ""), true);
          setProgress(prog);
          updateNode(parentNodeId, { progress: prog });
          break;
        }

        case "log": {
          const line = String(p.line ?? "").trimEnd();
          if (line) setLogs(prev => [...prev, line].slice(-600));
          break;
        }

        case "profile_enrichment": {
          const url     = String(p.url ?? "");
          const siteKey = String(p.site ?? "");
          const name    = String(p.name ?? "");
          const bio     = String(p.bio ?? "");
          const avatar  = String(p.avatar_url ?? "");
          const blog    = String(p.blog ?? "");
          const loc     = String(p.location ?? "");
          const company = String(p.company ?? "");
          const follows = String(p.followers ?? "");
          const created = String(p.created_at ?? "");
          const extra   = (p.extra && typeof p.extra === "object")
            ? p.extra as Record<string, string>
            : {};

          const humanUrl = String(p.human_url ?? "");
          const existingId = urlToNodeId.current.get(url)
            || (humanUrl ? urlToNodeId.current.get(humanUrl) : undefined);

          if (!existingId) break;

          const enriched: InfoField[] = [];
          const push = (key: string, label: string, value: string, opts: Partial<InfoField> = {}) => {
            if (value) enriched.push({ key, label, value, editable: false, ...opts });
          };

          if (avatar && isAvatarUrl(avatar)) {
            enriched.push({ key: "avatar", label: "Photo", value: avatar, editable: false, isImage: true });
          }
          push("name", "Name", name);
          push("bio", "Bio", bio);
          push("location", "Location", loc);
          push("company", "Company", company);
          push("blog", "Website", blog, { isLink: true });
          push("followers", "Followers", follows);
          push("created_at", "Joined", created);
          push("site", "Platform", siteKey);
          push("url", "URL", url, { isLink: true });
          for (const [k, v] of Object.entries(extra)) {
            if (v && String(v).trim()) {
              push(k, k.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()), String(v).slice(0, 120));
            }
          }

          const newLabel = name || String(p.username ?? "");

          // Scraped profile data — the source is the scraping layer,
          // so the confidence comes from the same table the backend
          // uses for its own graph.
          const conf = confidenceForFinding(p);

          updateNode(existingId, {
            infoFields: enriched,
            ...(newLabel ? { label: newLabel } : {}),
            ...(conf !== undefined ? { confidence: conf } : {}),
          });
          break;
        }

        case "finding": {
          const ftype = String(p.type ?? "");
          if (SKIP_TYPES.has(ftype)) break;

          if (ftype === "profile_url") {
            const url = String(p.url ?? "");
            if (isNoisyUrl(url)) break;
          }

          if (shouldSkipAsDuplicate(parentNodeId, ftype, p)) break;

          const category = FINDING_CATEGORIES[ftype] ?? "other";
          const stageNow = currentStageRef.current;
          const confidence = confidenceForFinding(p);

          setFindings(prev => {
            const entry: Finding = {
              id:        nextFindingId(),
              stage:     String(stageNow ?? ""),
              type:      ftype,
              category,
              label:     extractLabel(ftype, p),
              timestamp: Date.now(),
              payload:   p as FindingPayload,
            };
            return [entry, ...prev].slice(0, 200);
          });

          if (ftype === "api_response") {
            const url    = String(p.url ?? "");
            const label  = String(p.label ?? "");
            const infoFields = buildInfoFields(ftype, p);

            const nodeLabel = label || `api: ${url.replace(/^https?:\/\//, "").slice(0, 40)}`;
            const position  = childPosition(parentPos, currentIndex++);
            const newNode: GraphNode = {
              id:            newNodeId(),
              label:         nodeLabel,
              entityType:    "url",
              module:        "probe",
              position,
              colour:        "#e0e7ff",
              investigating: false,
              progress:      0,
              infoFields,
              rawData:       p as Record<string, unknown>,
              createdAt:     Date.now(),
              confidence,
            };
            const newEdge: GraphEdge = {
              id:       newEdgeId(),
              sourceId: parentNodeId,
              targetId: newNode.id,
              colour:   "#000000",
              animated: true,
            };
            addNode(newNode);
            addEdge(newEdge);
            urlToNodeId.current.set(url, newNode.id);
            break;
          }

          const label = extractLabel(ftype, p);
          if (!label || label === ftype) break;

          const entityType: NodeEntityType = findingTypeToEntityType(ftype);
          const position = childPosition(parentPos, currentIndex++);
          const infoFields = buildInfoFields(ftype, p);

          const childNode: GraphNode = {
            id:            newNodeId(),
            label,
            entityType,
            module:        classifyInput(label).module,
            position,
            colour:        "#ffffff",
            investigating: false,
            progress:      0,
            infoFields,
            rawData:       p as Record<string, unknown>,
            createdAt:     Date.now(),
            confidence,
          };

          const edge: GraphEdge = {
            id:       newEdgeId(),
            sourceId: parentNodeId,
            targetId: childNode.id,
            colour:   "#000000",
            animated: true,
          };

          if (ftype === "profile_url") {
            const url = String(p.url ?? "");
            if (url) urlToNodeId.current.set(url, childNode.id);
          }

          addNode(childNode);
          addEdge(edge);
          break;
        }

        case "pivot_start": {
          const seed     = String(p.seed ?? "");
          const seedType = String(p.seed_type ?? "username") as "email" | "username";
          const depth    = Number(p.depth ?? 1);
          setPivotDepth(prev => Math.max(prev, depth));
          setPivots(prev => {
            if (prev.some(x => x.seed === seed)) return prev;
            return [...prev, { seed, seedType, depth, status: "running" }];
          });
          break;
        }

        case "pivot_done": {
          const seed = String(p.seed ?? "");
          setPivots(prev => prev.map(x =>
            x.seed === seed ? { ...x, status: "done" as PivotStatus } : x
          ));
          break;
        }

        case "pivot_error": {
          const seed = String(p.seed ?? "");
          setPivots(prev => prev.map(x =>
            x.seed === seed ? { ...x, status: "error" as PivotStatus } : x
          ));
          break;
        }

        case "pivot_skipped": {
          const seed = String(p.seed ?? "");
          setPivots(prev => prev.map(x =>
            x.seed === seed ? { ...x, status: "skipped" as PivotStatus } : x
          ));
          break;
        }

        case "pivot_confirm_timeout": {
          const depth  = p.depth ?? "?";
          const reason = String(p.reason ?? "timeout");
          const why = reason === "cancelled"
            ? "investigation cancelled"
            : "confirmation window elapsed";
          setLogs(prev => [
            ...prev,
            `[pivot] ${why} at depth ${depth} — skipping seeds`,
          ].slice(-600));
          break;
        }

        case "report_ready":
          if (p.format === "html") setReportUrl(String(p.path ?? ""));
          break;

        case "abort": {
          const reason = String(p.reason ?? "aborted");
          setLogs(prev => [...prev, `[abort] ${reason}`].slice(-600));
          break;
        }

        case "stream_end": {
          setProgress(100);
          setCurrentStage(null);

          const serverStatus = String(p.status ?? "done");
          let finalStatus: InvestigationStatus;
          if (serverStatus === "cancelled")   finalStatus = "cancelled";
          else if (serverStatus === "error")  finalStatus = "error";
          else                                finalStatus = "done";
          setStatus(finalStatus);

          updateNode(parentNodeId, {
            investigating: false,
            progress: finalStatus === "error" ? 0 : 100,
          });
          if (p.report_url) setReportUrl(String(p.report_url));
          parentNextIndex.current.set(parentNodeId, currentIndex);

          setRunning(false);
          setStopping(false);
          break;
        }

        case "error":
          setStatus("error");
          updateNode(parentNodeId, { investigating: false, progress: 0 });
          setCurrentStage(null);
          setRunning(false);
          setStopping(false);
          break;
      }
    };

    (async () => {
      try {
        const res = await apiFetch(runUrl(), {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify(params),
          signal:  controller.signal,
        });

        if (!res.ok) {
          const text = await res.text().catch(() => "");
          setLogs(prev => [
            ...prev,
            `[error] /run returned HTTP ${res.status}: ${text.slice(0, 200)}`,
          ].slice(-600));
          setStatus("error");
          setRunning(false);
          setStopping(false);
          updateNode(parentNodeId, { investigating: false, progress: 0 });
          return;
        }

        if (!res.body) {
          setLogs(prev => [...prev, "[error] /run returned no response body"].slice(-600));
          setStatus("error");
          setRunning(false);
          setStopping(false);
          updateNode(parentNodeId, { investigating: false, progress: 0 });
          return;
        }

        const reader  = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";

          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const raw = line.slice(6).trim();
            if (!raw) continue;
            try {
              const parsed = JSON.parse(raw) as { type: string; payload: Record<string, unknown> };
              handleEvent(parsed);
            } catch {
              // Ignore malformed frames.
            }
          }
        }

        setRunning(prev => {
          if (prev) {
            updateNode(parentNodeId, { investigating: false, progress: 0 });
            setCurrentStage(null);
          }
          return false;
        });
        setStopping(false);
      } catch (err: unknown) {
        if ((err as Error)?.name === "AbortError") {
          // Expected on unmount or when start() is called again.
        } else {
          setLogs(prev => [...prev, `[sse] error: ${err}`].slice(-600));
          setStatus("error");
          updateNode(parentNodeId, { investigating: false, progress: 0 });
          setRunning(false);
          setStopping(false);
        }
      } finally {
        if (abortRef.current === controller) {
          abortRef.current = null;
        }
      }
    })();
  }, [addNode, addEdge, updateNode, shouldSkipAsDuplicate]);

  return {
    progress, running, stopping, jobId, reportUrl, logs, currentStage,
    status, target, mode, pivotDepth, pivots, findings,
    start, stop, resetParentCounter,
  };
}