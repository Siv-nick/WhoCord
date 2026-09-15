// src/types/graph.ts
// ─────────────────────────────────────────────────────────────────────────────
// TypeScript types for the Interactive Investigation Canvas.

// ---------------------------------------------------------------------------
// Entity type discriminator
// ---------------------------------------------------------------------------

export type NodeEntityType =
  | "username"
  | "email"
  | "phone"
  | "domain"
  | "url"
  | "social_profile"
  | "image"
  | "breach"
  | "ip"
  | "name"
  | "location"
  | "unknown";

// ---------------------------------------------------------------------------
// Investigation module that created / can be run on this node
// ---------------------------------------------------------------------------

export type NodeModule =
  | "manual"
  | "discord"
  | "email"
  | "domain"
  | "phone"
  | "image"
  | "url"
  | "probe"
  | "root";

// ---------------------------------------------------------------------------
// A single info-card field (editable key/value pair)
// ---------------------------------------------------------------------------

export interface InfoField {
  key:      string;
  label:    string;
  value:    string;
  editable: boolean;
  url?:     string;
  isImage?: boolean;
  isLink?:  boolean;
}

// ---------------------------------------------------------------------------
// Core graph node
// ---------------------------------------------------------------------------

export interface GraphNode {
  id:         string;
  label:      string;
  entityType: NodeEntityType;
  module:     NodeModule;
  position:   { x: number; y: number };
  colour:     string;
  investigating: boolean;
  progress:   number;
  infoFields: InfoField[];
  rawData:    Record<string, unknown>;
  createdAt:  number;
  confidence?: number;
}

// ---------------------------------------------------------------------------
// Directed edge between two nodes
// ---------------------------------------------------------------------------

export interface GraphEdge {
  id:       string;
  sourceId: string;
  targetId: string;
  label?:   string;
  colour:   string;
  animated: boolean;
}

// ---------------------------------------------------------------------------
// Viewport state (pan + zoom)
// ---------------------------------------------------------------------------

export interface Viewport {
  x:    number;
  y:    number;
  zoom: number;
}

// ---------------------------------------------------------------------------
// Serialisable map save file
// ---------------------------------------------------------------------------

export interface MapSaveFile {
  version:  string;
  savedAt:  string;
  nodes:    GraphNode[];
  edges:    GraphEdge[];
  viewport: Viewport;
}

// ---------------------------------------------------------------------------
// Filter state
// ---------------------------------------------------------------------------

export interface FilterState {
  types:      Set<NodeEntityType>;
  searchText: string;
}

// ---------------------------------------------------------------------------
// Node popup action
// ---------------------------------------------------------------------------

export type NodePopupAction = "connect" | "view_details" | "investigate" | null;

// ---------------------------------------------------------------------------
// Chat message
// ---------------------------------------------------------------------------

export type ChatRole = "user" | "assistant";

export type ChatErrorKind =
  | "not_configured"
  | "rate_limited"
  | "provider_error"
  | "network";

export interface ChatMessage {
  id:      string;
  role:    ChatRole;
  content: string;
  ts:      number;
  /**
   * Set when the message is an error notice rather than content. The
   * UI uses this to render an icon and a friendlier tone; the raw
   * provider detail lives in errorRaw so a developer can still see it.
   */
  errorKind?: ChatErrorKind;
  /** Raw provider text, kept for debugging. Not rendered by default. */
  errorRaw?: string;
}