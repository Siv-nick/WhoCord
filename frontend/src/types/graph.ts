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
  isImage?: boolean;   // added
  isLink?:  boolean;   // added
}

// ---------------------------------------------------------------------------
// Core graph node
// ---------------------------------------------------------------------------

export interface GraphNode {
  id:         string;
  /** Display label shown under the node icon */
  label:      string;
  /** Classified entity type – drives the icon */
  entityType: NodeEntityType;
  /** Which module produced / should investigate this node */
  module:     NodeModule;
  /** Canvas position in logical (unscaled) coordinates */
  position:   { x: number; y: number };
  /** Fill colour – CSS colour string, default "#ffffff" */
  colour:     string;
  /** Whether an investigation is currently running from this node */
  investigating: boolean;
  /** 0–100, shown when investigating === true */
  progress:   number;
  /** Structured data for the Info Card */
  infoFields: InfoField[];
  /** Raw finding payload for reference */
  rawData:    Record<string, unknown>;
  /** Timestamp when node was added (ms) */
  createdAt:  number;
}

// ---------------------------------------------------------------------------
// Directed edge between two nodes
// ---------------------------------------------------------------------------

export interface GraphEdge {
  id:       string;
  sourceId: string;
  targetId: string;
  /** Optional label shown mid-edge */
  label?:   string;
  /** Edge colour – CSS colour string, default "#000000" */
  colour:   string;
  /** Whether this edge is animated (newly created) */
  animated: boolean;
}

// ---------------------------------------------------------------------------
// Viewport state (pan + zoom)
// ---------------------------------------------------------------------------

export interface Viewport {
  x:    number;   // pan offset in px
  y:    number;
  zoom: number;   // 0.2 – 3.0
}

// ---------------------------------------------------------------------------
// Serialisable map save file
// ---------------------------------------------------------------------------

export interface MapSaveFile {
  version:  string;
  savedAt:  string;    // ISO timestamp
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

export interface ChatMessage {
  id:      string;
  role:    ChatRole;
  content: string;
  ts:      number;
}
