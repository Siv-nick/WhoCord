// src/utils/api.ts
//
// Change log
// ----------
// - Auth is now cookie-based. The token no longer lives in a <meta>
//   tag, and no URL carries ?token=. Every fetch uses
//   credentials: "same-origin" so the browser attaches the
//   HttpOnly whocord_session cookie automatically.
// - investigationReportUrl returns a plain URL — the iframe and
//   anchor tag carry the cookie on the request.

import type {
  AppConfig,
  CostSummary,
  EnrichmentTestResult,
  Job,
  LLMConfig,
  OutputFormat,
  PivotConfig,
  PivotSeed,
  RunParams,
} from "../types/investigation";

export type { LLMConfig } from "../types/investigation";

const BASE = "";

// ---------------------------------------------------------------------------
// Fetch with credentials
// ---------------------------------------------------------------------------

export function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, {
    ...init,
    // The session lives in an HttpOnly cookie. Without this flag the
    // browser would omit it on any same-origin fetch that happens to
    // default to omit (older specs, some polyfills).
    credentials: "same-origin",
  });
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export async function fetchConfig(): Promise<AppConfig> {
  const res = await apiFetch(`${BASE}/get_config`);
  if (!res.ok) throw new Error(`/get_config ${res.status}`);
  return res.json();
}

export async function setToken(key: string, value: string): Promise<void> {
  await apiFetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "set_token", key, value }),
  });
}

export async function toggleTool(key: string, enable: boolean): Promise<void> {
  await apiFetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "toggle_tool", key, enable }),
  });
}

export async function setMode(mode: string): Promise<void> {
  await apiFetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "set_mode", mode }),
  });
}

export async function toggleDebug(): Promise<{ debug: boolean }> {
  const res = await apiFetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "toggle_debug" }),
  });
  return res.json();
}

export async function saveOutputFormat(fmt: OutputFormat): Promise<void> {
  const res = await apiFetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "set_output_format", format: fmt }),
  });
  if (!res.ok) throw new Error(`set_output_format ${res.status}`);
}

// ---------------------------------------------------------------------------
// Pivot config
// ---------------------------------------------------------------------------

export async function savePivotConfig(pivot: PivotConfig): Promise<void> {
  await apiFetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "set_pivot", pivot }),
  });
}

// ---------------------------------------------------------------------------
// Enrichment config
// ---------------------------------------------------------------------------

export interface EnrichmentPatch {
  max_identifiers?: number;
  phone_reveal?:    boolean;
}

export async function saveEnrichmentConfig(
  patch: EnrichmentPatch,
): Promise<void> {
  const res = await apiFetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "set_enrichment", enrichment: patch }),
  });
  if (!res.ok) throw new Error(`set_enrichment ${res.status}`);
}

export async function testEnrichmentProvider(
  provider: "apollo" | "lusha",
): Promise<EnrichmentTestResult> {
  try {
    const res = await apiFetch(`${BASE}/api/enrichment/test/${provider}`, {
      method: "POST",
    });
    const body = await res.json().catch(() => ({}));
    return body as EnrichmentTestResult;
  } catch (err) {
    return { ok: false, balance: null, error: String(err) };
  }
}

// ---------------------------------------------------------------------------
// LLM models
// ---------------------------------------------------------------------------

export interface LLMModel {
  id:        string;
  owned_by:  string;
  free?:     boolean;
  created?:  number;
}

export interface LLMModelList {
  models:  LLMModel[];
  source:  "live" | "fallback";
  reason?: string;
}

export async function fetchLLMModels(): Promise<LLMModelList> {
  const res = await apiFetch(`${BASE}/api/llm/models`);
  if (!res.ok) throw new Error(`/api/llm/models ${res.status}`);
  return res.json();
}

export async function fetchGroqModels(): Promise<LLMModelList> {
  return fetchLLMModels();
}

export async function saveLLMConfig(llm: Partial<LLMConfig>): Promise<void> {
  const res = await apiFetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "set_llm", llm }),
  });
  if (!res.ok) throw new Error(`set_llm ${res.status}`);
}

// ---------------------------------------------------------------------------
// Pivot confirmation
// ---------------------------------------------------------------------------

export async function confirmPivot(
  jobId: string,
  approvedSeeds: PivotSeed[],
): Promise<void> {
  await apiFetch(`${BASE}/api/pivot/confirm/${jobId}`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ approved_seeds: approvedSeeds }),
  });
}

// ---------------------------------------------------------------------------
// Stop
// ---------------------------------------------------------------------------

export interface StopResult {
  success: boolean;
  job_id?: string;
  error?:  string;
}

export async function stopInvestigation(jobId?: string): Promise<StopResult> {
  try {
    const res = await apiFetch(`${BASE}/stop`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(jobId ? { job_id: jobId } : {}),
    });
    const body = await res.json().catch(() => ({} as StopResult));
    return body as StopResult;
  } catch (err) {
    return { success: false, error: String(err) };
  }
}

// ---------------------------------------------------------------------------
// Investigations — paginated
// ---------------------------------------------------------------------------

export interface JobPage {
  jobs:   Job[];
  total:  number;
  limit:  number;
  offset: number;
}

export interface FetchJobsOptions {
  caseId?: string;
  limit?:  number;
  offset?: number;
}

export async function fetchInvestigations(
  opts: FetchJobsOptions = {},
): Promise<JobPage> {
  const params = new URLSearchParams();
  if (opts.caseId !== undefined) params.set("case_id", opts.caseId);
  if (opts.limit  !== undefined) params.set("limit",  String(opts.limit));
  if (opts.offset !== undefined) params.set("offset", String(opts.offset));

  const qs = params.toString();
  const url = `${BASE}/api/investigations${qs ? `?${qs}` : ""}`;
  const res = await apiFetch(url);
  if (!res.ok) throw new Error(`/api/investigations ${res.status}`);
  return res.json();
}

export interface CaseDetailPage {
  case: {
    case_id:       string;
    job_count:     number;
    first_started: string;
    last_started:  string;
    targets:       string[];
  };
  jobs:   Job[];
  total:  number;
  limit:  number;
  offset: number;
}

export async function fetchCase(
  caseId: string,
  opts: { limit?: number; offset?: number } = {},
): Promise<CaseDetailPage> {
  const params = new URLSearchParams();
  if (opts.limit  !== undefined) params.set("limit",  String(opts.limit));
  if (opts.offset !== undefined) params.set("offset", String(opts.offset));
  const qs = params.toString();
  const url = `${BASE}/api/cases/${encodeURIComponent(caseId)}${qs ? `?${qs}` : ""}`;
  const res = await apiFetch(url);
  if (!res.ok) throw new Error(`/api/cases/${caseId} ${res.status}`);
  return res.json();
}

export async function fetchInvestigationIntel(id: string): Promise<unknown> {
  const res = await apiFetch(`${BASE}/api/investigations/${id}`);
  if (!res.ok) throw new Error(`/api/investigations/${id} ${res.status}`);
  return res.json();
}

export interface DeleteResult {
  success:        boolean;
  job_id?:        string;
  files_removed?: string[];
  error?:         string;
}

export async function deleteInvestigation(id: string): Promise<DeleteResult> {
  try {
    const res = await apiFetch(`${BASE}/api/investigations/${id}`, {
      method: "DELETE",
    });
    const body = await res.json().catch(() => ({} as DeleteResult));
    return body as DeleteResult;
  } catch (err) {
    return { success: false, error: String(err) };
  }
}

/**
 * URL of the HTML report for a job.
 *
 * No token parameter — the HttpOnly session cookie is attached by the
 * browser on the top-level navigation (same-origin anchor) and on the
 * iframe request. The report route enforces the sandbox CSP header,
 * so the response is safe to frame even without an explicit sandbox
 * attribute on the caller's element.
 */
export function investigationReportUrl(id: string): string {
  return `${BASE}/api/investigations/${id}/report`;
}

export async function fetchJobCost(jobId: string): Promise<CostSummary | null> {
  if (!jobId) return null;
  try {
    const res = await apiFetch(`${BASE}/api/investigations/${jobId}/cost`);
    if (!res.ok) return null;
    const body = await res.json();
    if (!body || typeof body !== "object") return null;
    return body as CostSummary;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Batch
// ---------------------------------------------------------------------------

export interface BatchStartResult {
  batch_id:        string;
  case_id:         string;
  job_ids:         string[];
  targets_queued:  number;
  targets_skipped: number;
  error?:          string;
}

export interface BatchJobRow {
  job_id:     string;
  target:     string;
  status:     string;
  has_report: boolean;
  has_intel:  boolean;
}

export interface BatchDetail {
  batch_id:  string;
  case_id:   string;
  mode:      string;
  job_count: number;
  jobs:      BatchJobRow[];
}

export async function startBatch(
  targets: string[],
  mode: string,
  caseId?: string,
): Promise<BatchStartResult> {
  const res = await apiFetch(`${BASE}/api/batch`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ targets, mode, case_id: caseId ?? "" }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(
      (body as { error?: string }).error ?? `batch start failed: ${res.status}`,
    );
  }
  return res.json();
}

export async function fetchBatch(batchId: string): Promise<BatchDetail> {
  const res = await apiFetch(`${BASE}/api/batch/${batchId}`);
  if (!res.ok) throw new Error(`batch fetch failed: ${res.status}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

export function runUrl(): string {
  return `${BASE}/run`;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

export function upgradeToolsUrl(): string {
  return `${BASE}/upgrade_tools`;
}

export async function shutdownServer(): Promise<void> {
  await apiFetch(`${BASE}/shutdown`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ confirm: "yes" }),
  }).catch(() => {});
}