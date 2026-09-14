// src/utils/api.ts
import type {
  AppConfig,
  EnrichmentTestResult,
  Job,
  LLMConfig,
  PivotConfig,
  PivotSeed,
  RunParams,
} from "../types/investigation";

export type { LLMConfig } from "../types/investigation";

const BASE = "";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export async function fetchConfig(): Promise<AppConfig> {
  const res = await fetch(`${BASE}/get_config`);
  if (!res.ok) throw new Error(`/get_config ${res.status}`);
  return res.json();
}

export async function setToken(key: string, value: string): Promise<void> {
  await fetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "set_token", key, value }),
  });
}

export async function toggleTool(key: string, enable: boolean): Promise<void> {
  await fetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "toggle_tool", key, enable }),
  });
}

export async function setMode(mode: string): Promise<void> {
  await fetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "set_mode", mode }),
  });
}

export async function toggleDebug(): Promise<{ debug: boolean }> {
  const res = await fetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "toggle_debug" }),
  });
  return res.json();
}

// ---------------------------------------------------------------------------
// Pivot config
// ---------------------------------------------------------------------------

export async function savePivotConfig(pivot: PivotConfig): Promise<void> {
  await fetch(`${BASE}/config`, {
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
  const res = await fetch(`${BASE}/config`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ action: "set_enrichment", enrichment: patch }),
  });
  if (!res.ok) throw new Error(`set_enrichment ${res.status}`);
}

/**
 * Test a stored API key against the provider's account endpoint.
 * This never spends a credit — both providers expose a 0-cost
 * profile/usage endpoint.
 */
export async function testEnrichmentProvider(
  provider: "apollo" | "lusha",
): Promise<EnrichmentTestResult> {
  try {
    const res = await fetch(`${BASE}/api/enrichment/test/${provider}`, {
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
  const res = await fetch(`${BASE}/api/llm/models`);
  if (!res.ok) throw new Error(`/api/llm/models ${res.status}`);
  return res.json();
}

/** @deprecated Use fetchLLMModels — the endpoint was renamed. */
export async function fetchGroqModels(): Promise<LLMModelList> {
  return fetchLLMModels();
}

export async function saveLLMConfig(llm: Partial<LLMConfig>): Promise<void> {
  const res = await fetch(`${BASE}/config`, {
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
  await fetch(`${BASE}/api/pivot/confirm/${jobId}`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ approved_seeds: approvedSeeds }),
  });
}

// ---------------------------------------------------------------------------
// Stop investigation
// ---------------------------------------------------------------------------

export interface StopResult {
  success: boolean;
  job_id?: string;
  error?:  string;
}

export async function stopInvestigation(jobId?: string): Promise<StopResult> {
  try {
    const res = await fetch(`${BASE}/stop`, {
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
// Investigations
// ---------------------------------------------------------------------------

export async function fetchInvestigations(): Promise<Job[]> {
  const res = await fetch(`${BASE}/api/investigations`);
  if (!res.ok) throw new Error(`/api/investigations ${res.status}`);
  return res.json();
}

export async function fetchInvestigationIntel(id: string): Promise<unknown> {
  const res = await fetch(`${BASE}/api/investigations/${id}`);
  if (!res.ok) throw new Error(`/api/investigations/${id} ${res.status}`);
  return res.json();
}

export function investigationReportUrl(id: string): string {
  return `${BASE}/api/investigations/${id}/report`;
}

// ---------------------------------------------------------------------------
// Run – SSE URL builder
// ---------------------------------------------------------------------------

export function buildRunUrl(params: RunParams): string {
  const qs = new URLSearchParams();
  qs.set("mode", params.mode);
  if (params.username)    qs.set("username",    params.username);
  if (params.email)       qs.set("email",        params.email);
  if (params.user_id)     qs.set("user_id",      params.user_id);
  if (params.guild_id)    qs.set("guild_id",     params.guild_id);
  if (params.multi_guild) qs.set("multi_guild", "1");
  if (params.target)      qs.set("target",       params.target);
  return `${BASE}/run?${qs.toString()}`;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

export function upgradeToolsUrl(): string {
  return `${BASE}/upgrade_tools`;
}

export async function shutdownServer(): Promise<void> {
  await fetch(`${BASE}/shutdown`, { method: "POST" }).catch(() => {});
}