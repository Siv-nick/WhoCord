// src/types/investigation.ts
import type { IconName } from "../components/Icons";

export type InvestigationMode =
  | "manual" | "discord" | "email" | "domain" | "phone" | "image" | "url" | "probe";

export type InvestigationStatus =
  | "idle" | "running" | "stopping" | "done" | "cancelled" | "error";

export type EventType =
  | "job_start" | "stage_start" | "stage_done" | "stage_error"
  | "abort" | "progress" | "finding" | "report_ready"
  | "pivot_start" | "pivot_done" | "pivot_error" | "pivot_skipped"
  | "pivot_confirm_request" | "pivot_confirm_timeout"
  | "log" | "done" | "error" | "heartbeat" | "stream_end"
  | "profile_enrichment";

export interface SSEEvent {
  type:    EventType;
  payload: Record<string, unknown>;
}

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

export interface Job {
  id:            string;
  target:        string;
  mode:          InvestigationMode | string;
  case_id:       string;
  started_at:    string;
  status:        "running" | "done" | "cancelled" | "error";
  has_report:    boolean;
  has_intel:     boolean;
  has_manifest?: boolean;
}

export interface TokenStatus {
  DISCORD_TOKEN:      boolean;
  GITHUB_TOKEN:       boolean;
  GROQ_API_KEY:       boolean;
  OPENROUTER_API_KEY: boolean;
  HIBP_API_KEY:       boolean;
  INSTAGRAM_SESSION:  boolean;
  APOLLO_API_KEY:     boolean;
  LUSHA_API_KEY:      boolean;
  CORD_CAT_API_KEY:   boolean;
  TINEYE_API_KEY:     boolean;
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

export type LLMProvider = "groq" | "openrouter" | "ollama";

export interface LLMConfig {
  provider:            LLMProvider;
  model:               string;
  temperature:         number;
  max_tokens:          number;
  system_prompt:       string;
  intel_budget:        number;
  intel_include_raw:   boolean;
  intel_exclude_meta:  boolean;
}

export type EnrichmentProvider = "apollo" | "lusha";

export interface EnrichmentConfig {
  max_identifiers: number;
  phone_reveal:    boolean;
  enabled: {
    apollo: boolean;
    lusha:  boolean;
  };
  keys_stored: {
    apollo: boolean;
    lusha:  boolean;
  };
}

export interface EnrichmentTestResult {
  ok:      boolean;
  balance: number | Record<string, number | null> | null;
  error:   string | null;
}

export type OutputFormat = "html" | "markdown" | "json";

export interface AppConfig {
  tokens:             TokenStatus;
  tools:              ToolConfig[];
  mode:               string;
  multi_guild_search: boolean;
  debug:              boolean;
  output_format:      OutputFormat;
  retention_days:     number;
  pivot:              PivotConfig;
  llm:                LLMConfig;
  enrichment:         EnrichmentConfig;
}

export interface RunParams {
  mode:         InvestigationMode;
  username?:    string;
  email?:       string;
  user_id?:     string;
  guild_id?:    string;
  multi_guild?: boolean;
  target?:      string;
  case_id?:     string;
}

export interface ModuleMeta {
  id:               InvestigationMode;
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

// ---------------------------------------------------------------------------
// Cost tracking (Phase 4)
// ---------------------------------------------------------------------------

export interface CostBreakdownEntry {
  kind:            "llm" | "enrichment";
  service?:        string;
  model?:          string;
  bytes_in?:       number;
  bytes_out?:      number;
  est_tokens_in?:  number;
  est_tokens_out?: number;
  cost_usd?:       number;
  ok?:             boolean;
  provider?:       string;
  credits?:        number;
  matched?:        number;
}

export interface CostSummary {
  job_id:              string;
  available:           boolean;
  reason?:             string;
  llm_calls:           number;
  llm_bytes_in:        number;
  llm_bytes_out:       number;
  llm_est_tokens_in:   number;
  llm_est_tokens_out:  number;
  llm_cost_usd:        number;
  enrichment_calls:    number;
  enrichment_credits:  number;
  breakdown:           CostBreakdownEntry[];
}