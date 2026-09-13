// src/types/investigation.ts
// All structured types – Phase 4 extended.

import type { IconName } from "../components/Icons";

// ---------------------------------------------------------------------------
// Investigation modes
// ---------------------------------------------------------------------------

export type InvestigationMode =
  | "manual"
  | "discord"
  | "email"
  | "domain"
  | "phone"
  | "image"
  | "url"
  | "probe";

// ---------------------------------------------------------------------------
// SSE event envelope
// ---------------------------------------------------------------------------

export type EventType =
  | "job_start"
  | "stage_start"
  | "stage_done"
  | "stage_error"
  | "abort"
  | "progress"
  | "finding"
  | "report_ready"
  | "pivot_start"
  | "pivot_done"
  | "pivot_error"
  | "pivot_skipped"
  | "pivot_confirm_request"
  | "pivot_confirm_timeout"
  | "log"
  | "done"
  | "error"
  | "heartbeat"
  | "stream_end"
  | "profile_enrichment";

export interface SSEEvent {
  type:    EventType;
  payload: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Pivot types
// ---------------------------------------------------------------------------

export interface PivotSeed {
  value: string;
  type:  "email" | "username";
}

export interface PivotConfirmRequestPayload {
  job_id:          string;
  depth:           number;
  seeds:           PivotSeed[];
  timeout_seconds: number;
}

export type PivotStatus = "pending_confirm" | "running" | "done" | "error" | "skipped";

export interface PivotInfo {
  seed:     string;
  seedType: "email" | "username";
  depth:    number;
  status:   PivotStatus;
}

// ---------------------------------------------------------------------------
// Finding payload
// ---------------------------------------------------------------------------

export interface FindingPayload {
  type:               string;
  value?:             string;
  email?:             string;
  url?:               string;
  domain?:            string;
  source?:            string;
  platform?:          string;
  sites?:             string[];
  breaches?:          number;
  count?:             number;
  entity_count?:      number;
  correlation_count?: number;
  has_narrative?:     boolean;
  correlations?:      Array<{ type: string; description: string; confidence: number }>;
  detected_type?:     string;
  records?:           Record<string, string[]>;
  data?:              Record<string, unknown>;
  threats?:           string[];
  is_safe?:           boolean;
  file?:              string;
  url_count?:         number;
  emails?:            string[];
  [key: string]:      unknown;
}

// ---------------------------------------------------------------------------
// Stage state
// ---------------------------------------------------------------------------

export type StageStatus = "pending" | "running" | "done" | "error" | "aborted";

export interface StageState {
  name:          string;
  displayName:   string;
  status:        StageStatus;
  depth:         number;
  startedAt?:    number;
  finishedAt?:   number;
  errorMessage?: string;
}

// ---------------------------------------------------------------------------
// Finding card
// ---------------------------------------------------------------------------

export type FindingCategory =
  | "identity" | "email" | "social" | "breach"
  | "media"    | "intelligence" | "pivot"
  | "network"  | "phone" | "url" | "probe" | "other";

export interface Finding {
  id:        string;
  stage:     string;
  type:      string;
  category:  FindingCategory;
  label:     string;
  detail?:   string;
  timestamp: number;
  payload:   FindingPayload;
}

// ---------------------------------------------------------------------------
// Investigation live state
// ---------------------------------------------------------------------------

export interface InvestigationState {
  jobId:               string | null;
  target:              string;
  mode:                InvestigationMode | "";
  status:              "idle" | "running" | "done" | "error";
  stages:              StageState[];
  findings:            Finding[];
  logs:                string[];
  currentStage:        string | null;
  reportUrl:           string | null;
  pivotDepth:          number;
  pivots:              PivotInfo[];
  pivotConfirmPending: PivotConfirmRequestPayload | null;
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

export interface Job {
  id:         string;
  target:     string;
  mode:       InvestigationMode | string;
  started_at: string;
  status:     "running" | "done" | "error";
  has_report: boolean;
  has_intel:  boolean;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface TokenStatus {
  DISCORD_TOKEN:     boolean;
  GITHUB_TOKEN:      boolean;
  GROQ_API_KEY:      boolean;
  INSTAGRAM_SESSION: boolean;
}

export interface ToolConfig {
  key:     string;
  desc:    string;
  enabled: boolean;
}

export interface PivotConfig {
  enabled:         boolean;
  pivot_email:     boolean;
  pivot_username:  boolean;
  max_depth:       number;
  max_seeds:       number;
  require_confirm: boolean;
}

export interface AppConfig {
  tokens:             TokenStatus;
  tools:              ToolConfig[];
  mode:               string;
  multi_guild_search: boolean;
  debug:              boolean;
  pivot:              PivotConfig;
}

// ---------------------------------------------------------------------------
// Run parameters
// ---------------------------------------------------------------------------

export interface RunParams {
  mode:         InvestigationMode;
  username?:    string;
  email?:       string;
  user_id?:     string;
  guild_id?:    string;
  multi_guild?: boolean;
  target?:      string;
}

// ---------------------------------------------------------------------------
// Module metadata (used by Dashboard module cards)
// ---------------------------------------------------------------------------

export interface ModuleMeta {
  id:               InvestigationMode;
  /** Icon name from the Icons registry (not an emoji). */
  icon:             IconName;
  title:            string;
  description:      string;
  color:            string;
  inputLabel:       string;
  inputPlaceholder: string;
  inputType:        "text" | "email" | "url" | "tel";
  extraFields?: Array<{
    name:        string;
    label:       string;
    placeholder: string;
    required:    boolean;
    type:        "text" | "checkbox";
  }>;
}