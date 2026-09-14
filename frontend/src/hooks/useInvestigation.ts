// src/hooks/useInvestigation.ts
// Connects an SSE stream (/run) to the canvas graph state and exposes
// status / findings / pivots so the AI chat can include them.
//
// Stop plumbing
// -------------
// `stop()` calls the /stop endpoint with the current job id, tracks a
// `stopping` state while the server acknowledges, and lets the pipeline
// tear down cleanly at the next stage boundary. The old `stop()`
// implementation was purely client-side — it closed the EventSource
// while the server kept running the investigation.

import { useCallback, useRef, useState } from "react";
import { buildRunUrl, stopInvestigation } from "../utils/api";
import { classifyInput, findingTypeToEntityType } from "../utils/classify";
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

  const esRef        = useRef<EventSource | null>(null);
  const urlToNodeId  = useRef<Map<string, string>>(new Map());
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

  const closeStream = useCallback(() => {
    esRef.current?.close();
    esRef.current = null;
  }, []);

  /**
   * Signal the running investigation to abort. The server sets a
   * cancellation token which the pipeline checks at the next stage
   * boundary; the stream then delivers an `abort` event and finally
   * `stream_end` with status="cancelled".
   *
   * We do NOT close the EventSource here — the stream needs to stay
   * open long enough to deliver the terminal event.
   */
  const stop = useCallback(async () => {
    if (!running && status !== "running") return;
    setStopping(true);
    setStatus("stopping");

    const result = await stopInvestigation(jobIdRef.current ?? undefined);
    if (!result.success) {
      // The server refused — job may have already finished. Surface it
      // but leave the stream alone in case it's mid-teardown.
      console.warn("stopInvestigation failed:", result.error);
      setStopping(false);
      // If the server says "job is not running", the stream will
      // deliver stream_end shortly. If it says something else, we
      // fall back to running state.
      if (result.error && !result.error.includes("not running")) {
        setStatus("running");
      }
    }
    // On success we stay in "stopping" until `stream_end` arrives.
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
    if (esRef.current) esRef.current.close();
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

    const sseUrl  = buildRunUrl(params);
    const es      = new EventSource(sseUrl);
    esRef.current = es;

    const parentNode = liveNodes.find(n => n.id === parentNodeId);
    const parentPos  = parentNode?.position ?? { x: 0, y: 0 };

    let currentIndex = startIndex;

    es.onmessage = (evt: MessageEvent) => {
      let parsed: { type: string; payload: Record<string, unknown> };
      try { parsed = JSON.parse(evt.data); }
      catch { return; }

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
          updateNode(existingId, {
            infoFields: enriched,
            ...(newLabel ? { label: newLabel } : {}),
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
          setFindings(prev => {
            const entry: Finding = {
              id:        nextFindingId(),
              stage:     String(currentStage ?? ""),
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
          // Emitted when the confirmation window elapses without a
          // response. We surface it in the logs so the analyst knows
          // the pivot ran with the full seed set (server default).
          setLogs(prev => [
            ...prev,
            `[pivot] confirmation window elapsed at depth ${p.depth ?? "?"} — running full seed set`,
          ].slice(-600));
          break;
        }

        case "report_ready":
          if (p.format === "html") setReportUrl(String(p.path ?? ""));
          break;

        case "abort": {
          // The pipeline stopped early (user cancel or a stage aborted).
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
          closeStream();
          break;
        }

        case "error":
          setStatus("error");
          updateNode(parentNodeId, { investigating: false, progress: 0 });
          setCurrentStage(null);
          setRunning(false);
          setStopping(false);
          closeStream();
          break;
      }
    };

    // Native EventSource will retry automatically. Only treat the
    // connection as failed if it can't be re-established — the hook
    // (not this one) tracks retry count. Here we just log.
    es.onerror = () => {
      setLogs(prev => [...prev, "[sse] connection interrupted — retrying…"].slice(-600));
    };
  }, [addNode, addEdge, updateNode, closeStream, shouldSkipAsDuplicate, currentStage]);

  return {
    progress, running, stopping, jobId, reportUrl, logs, currentStage,
    status, target, mode, pivotDepth, pivots, findings,
    start, stop, resetParentCounter,
  };
}