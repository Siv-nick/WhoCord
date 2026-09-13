// src/utils/api.ts
import type { AppConfig, Job, PivotConfig, PivotSeed, RunParams } from "../types/investigation";

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
// Pivot confirmation
// ---------------------------------------------------------------------------

/**
 * Send the user's approved seed list back to the waiting pipeline thread.
 *
 * @param jobId        Active job UUID
 * @param approvedSeeds  Seeds the user approved (subset of what was proposed)
 */
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
// Investigations – history
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
  if (params.username)   qs.set("username",    params.username);
  if (params.email)      qs.set("email",        params.email);
  if (params.user_id)    qs.set("user_id",      params.user_id);
  if (params.guild_id)   qs.set("guild_id",     params.guild_id);
  if (params.multi_guild) qs.set("multi_guild", "1");
  if (params.target) qs.set("target", params.target);
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
