// src/pages/GraphCanvas.tsx
// ─────────────────────────────────────────────────────────────────────────────
// Interactive investigation canvas.
//
// Perf notes
//   • nodeById: Map<id, GraphNode> memoized once; edge loop is now O(E)
//     instead of O(E × N).
//   • compactMode: above 200 nodes, node labels are suppressed on
//     non-selected nodes.
//   • A single shared <radialGradient id="node-glass"> is defined here and
//     referenced from every GraphNode.

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import {
  newEdgeId,
  newNodeId,
  useFilteredNodeIds,
  useGraphState,
  useSelectedNode,
} from "../hooks/useGraphState";
import { useInvestigation } from "../hooks/useInvestigation";
import { useToast } from "../components/Toast";
import { useTheme } from "../hooks/useTheme";

import CanvasGrid        from "../components/CanvasGrid";
import EdgeLine          from "../components/EdgeLine";
import GraphNodeComp     from "../components/GraphNode";
import NodePopup         from "../components/NodePopup";
import InfoCard          from "../components/InfoCard";
import LiveLogPanel      from "../components/LiveLogPanel";
import FilterPanel       from "../components/FilterPanel";
import ExportModal       from "../components/ExportModal";
import ChatPanel         from "../components/ChatPanel";
import CardListPanel     from "../components/CardListPanel";
import CanvasConfigPanel from "../components/CanvasConfigPanel";
import ThemePanel        from "../components/ThemePanel";
import CommandPalette, { type PaletteAction } from "../components/CommandPalette";
import { Icon, type IconName } from "../components/Icons";

import type { GraphEdge, GraphNode, NodeModule } from "../types/graph";
import type { InvestigationMode, RunParams } from "../types/investigation";
import { classifyInput, MODULE_LABELS } from "../utils/classify";
import { childPosition } from "../utils/graphLayout";

// ── Threshold above which nodes hide their labels ────────────────────
const COMPACT_NODE_THRESHOLD = 200;

const MODULE_INPUTS: Array<{
  id: NodeModule;
  icon: IconName;
  label: string;
  placeholder: string;
  inputType: string;
}> = [
  { id: "manual",  icon: "atSign",  label: "Username",   placeholder: "e.g. johndoe",                 inputType: "text"  },
  { id: "discord", icon: "message", label: "Discord",    placeholder: "User ID",                      inputType: "text"  },
  { id: "email",   icon: "mail",    label: "Email",      placeholder: "target@example.com",           inputType: "email" },
  { id: "domain",  icon: "globe",   label: "Domain",     placeholder: "example.com",                  inputType: "text"  },
  { id: "phone",   icon: "phone",   label: "Phone",      placeholder: "+1 555 000 0000",              inputType: "tel"   },
  { id: "image",   icon: "image",   label: "Image",      placeholder: "https://…/image.png",          inputType: "url"   },
  { id: "url",     icon: "link",    label: "URL",        placeholder: "https://example.com",          inputType: "url"   },
  { id: "probe",   icon: "search",  label: "Probe",      placeholder: "Paste anything to auto-detect", inputType: "text" },
];

const CANVAS_ID = "whocord-canvas";

export default function GraphCanvas() {
  const location = useLocation();
  const navigate = useNavigate();
  const navState = location.state as { rootNode?: GraphNode } | null;
  const toast    = useToast();
  const theme    = useTheme();

  const canvasRef       = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: window.innerWidth, h: window.innerHeight });

  const {
    nodes, edges, viewport,
    addNode, removeNode, updateNode,
    addEdge,
    selectNode,
    setViewport, panBy, zoomTo,
  } = useGraphState();

  const selectedNode = useSelectedNode();
  const filteredIds  = useFilteredNodeIds();

  // ── Memoized id → node lookup.  Edge render loop becomes O(E). ──────
  const nodeById = useMemo(() => {
    const m = new Map<string, GraphNode>();
    for (const n of nodes) m.set(n.id, n);
    return m;
  }, [nodes]);

  const compactMode = nodes.length > COMPACT_NODE_THRESHOLD;

  // ── UI state ───────────────────────────────────────────────────────
  const [showPopup,     setShowPopup]     = useState(false);
  const [showInfo,      setShowInfo]      = useState(false);
  const [showExport,    setShowExport]    = useState(false);
  const [showChat,      setShowChat]      = useState(false);
  const [showLogPanel,  setShowLogPanel]  = useState(false);
  const [showCardList,  setShowCardList]  = useState(false);
  const [showConfig,    setShowConfig]    = useState(false);
  const [showTheme,     setShowTheme]     = useState(false);
  const [paletteOpen,   setPaletteOpen]   = useState(false);
  const [highlightedNodeId, setHighlighted] = useState<string | null>(null);

  // ── Module form ────────────────────────────────────────────────────
  const [moduleFormOpen,     setModuleFormOpen]     = useState(false);
  const [moduleFormParentId, setModuleFormParentId] = useState<string | null>(null);
  const [moduleFormSelected, setModuleFormSelected] = useState<NodeModule | null>(null);
  const [moduleFormInput,    setModuleFormInput]    = useState("");
  const [moduleFormError,    setModuleFormError]    = useState("");

  const manualChildCounter = useRef<number>(0);

  const vpDragging = useRef(false);
  const vpLast     = useRef({ x: 0, y: 0 });

  const { start: startInvestigation, running, logs, currentStage } = useInvestigation();

  const rightPanelWidth = showChat ? 380 : showCardList ? 400 : showLogPanel ? 340 : 0;

  // ─────────────────────────────────────────────────────────────────
  // Effects
  // ─────────────────────────────────────────────────────────────────

  useEffect(() => {
    if (navState?.rootNode && nodes.length === 0) {
      addNode(navState.rootNode);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const onResize = () => setSize({ w: window.innerWidth, h: window.innerHeight });
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const lastStageRef = useRef<string | null>(null);
  useEffect(() => {
    if (!running && lastStageRef.current && logs.length > 0) {
      toast.push("success", "Investigation complete", "New findings were added to the canvas.");
      lastStageRef.current = null;
    }
    if (running) lastStageRef.current = currentStage;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);

  // ─────────────────────────────────────────────────────────────────
  // Focus helper
  // ─────────────────────────────────────────────────────────────────
  const focusNode = useCallback((nodeId: string) => {
    const node = nodes.find(n => n.id === nodeId);
    if (!node) return;
    setHighlighted(nodeId);
    setTimeout(() => setHighlighted(null), 1500);
    setViewport({
      x: (size.w / 2) - (node.position.x * viewport.zoom),
      y: (size.h / 2) - (node.position.y * viewport.zoom),
    });
  }, [nodes, size, viewport.zoom, setViewport]);

  // ─────────────────────────────────────────────────────────────────
  // Background pan handlers
  // ─────────────────────────────────────────────────────────────────
  const onBgPointerDown = useCallback((e: React.PointerEvent<SVGRectElement>) => {
    if (e.button !== 0) return;
    vpDragging.current = true;
    vpLast.current = { x: e.clientX, y: e.clientY };
    (e.target as SVGRectElement).setPointerCapture(e.pointerId);
    selectNode(null);
    setShowPopup(false);
  }, [selectNode]);

  const onBgPointerMove = useCallback((e: React.PointerEvent<SVGRectElement>) => {
    if (!vpDragging.current) return;
    const dx = e.clientX - vpLast.current.x;
    const dy = e.clientY - vpLast.current.y;
    vpLast.current = { x: e.clientX, y: e.clientY };
    panBy(dx, dy);
  }, [panBy]);

  const onBgPointerUp = useCallback(() => {
    vpDragging.current = false;
  }, []);

  const onWheel = useCallback((e: React.WheelEvent<SVGSVGElement>) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    zoomTo(viewport.zoom * delta);
  }, [viewport.zoom, zoomTo]);

  // ─────────────────────────────────────────────────────────────────
  // Node handlers — stable identities so memoized nodes skip re-renders
  // ─────────────────────────────────────────────────────────────────
  const handleNodeDragEnd = useCallback(
    (id: string, pos: { x: number; y: number }) => {
      updateNode(id, { position: pos });
    },
    [updateNode],
  );

  const handleNodeSelect = useCallback((id: string) => {
    selectNode(id);
    setShowPopup(true);
    setShowInfo(false);
  }, [selectNode]);

  const handleViewDetails = useCallback((nodeId: string) => {
    selectNode(nodeId);
    setShowInfo(true);
    setShowPopup(false);
  }, [selectNode]);

  const handleColourChange = useCallback(
    (id: string, colour: string) => updateNode(id, { colour }),
    [updateNode],
  );

  const openModuleForm = useCallback((
    parentId: string | null,
    prefill?: { module?: NodeModule; input?: string },
  ) => {
    setModuleFormParentId(parentId);
    setModuleFormSelected(prefill?.module ?? null);
    setModuleFormInput(prefill?.input ?? "");
    setModuleFormError("");
    setModuleFormOpen(true);
  }, []);

  const handleConnect = useCallback((nodeId: string) => {
    openModuleForm(nodeId);
  }, [openModuleForm]);

  const handleInvestigate = useCallback((nodeId: string) => {
    const node = nodeById.get(nodeId);
    if (!node) return;
    const { module } = classifyInput(node.label);
    openModuleForm(nodeId, { module, input: node.label });
  }, [nodeById, openModuleForm]);

  // ─────────────────────────────────────────────────────────────────
  // Submit module form → add child node + start SSE
  // ─────────────────────────────────────────────────────────────────
  const handleModuleFormSubmit = useCallback(() => {
    const parentId = moduleFormParentId;
    const modId    = moduleFormSelected;
    const input    = moduleFormInput.trim();

    if (!modId || !input) {
      setModuleFormError("Please choose a module and enter a target.");
      return;
    }

    let parentNode: GraphNode | undefined;
    if (parentId) {
      parentNode = nodeById.get(parentId);
      if (!parentNode) return;
    } else {
      const offset = nodes.length * 120;
      parentNode = {
        id: newNodeId(),
        label: "Investigation Root",
        entityType: "unknown",
        module: "root",
        position: { x: offset, y: 0 },
        colour: "#8b5cf6",
        investigating: false,
        progress: 0,
        infoFields: [],
        rawData: {},
        createdAt: Date.now(),
      };
      addNode(parentNode);
    }

    const childId = newNodeId();
    const { entityType } = classifyInput(input);
    const idx = manualChildCounter.current++;
    const position = childPosition(parentNode.position, idx);

    const childNode: GraphNode = {
      id: childId,
      label: input,
      entityType,
      module: modId,
      position,
      colour: "#ffffff",
      investigating: true,
      progress: 0,
      infoFields: [{ key: "target", label: "Target", value: input, editable: true }],
      rawData: {},
      createdAt: Date.now(),
    };

    const edge: GraphEdge = {
      id: newEdgeId(),
      sourceId: parentNode.id,
      targetId: childId,
      colour: "#000000",
      animated: true,
    };

    addNode(childNode);
    addEdge(edge);
    setModuleFormOpen(false);
    setShowLogPanel(true);
    setShowChat(false);
    setShowCardList(false);

    const mode = modId as InvestigationMode;
    const params: RunParams = { mode };
    if (modId === "discord")       params.user_id  = input;
    else if (modId === "manual")   params.username = input;
    else                            params.target   = input;

    startInvestigation(childId, params);
    toast.push("info", "Investigation started", `${MODULE_LABELS[modId]} · ${input}`);
  }, [moduleFormParentId, moduleFormSelected, moduleFormInput, nodes,
      nodeById, addNode, addEdge, startInvestigation, toast]);

  // ─────────────────────────────────────────────────────────────────
  // Info field edit
  // ─────────────────────────────────────────────────────────────────
  const handleInfoFieldChange = useCallback((
    nodeId: string, key: string, value: string,
  ) => {
    const node = nodeById.get(nodeId);
    if (!node) return;
    updateNode(nodeId, {
      infoFields: node.infoFields.map(f => (f.key === key ? { ...f, value } : f)),
    });
  }, [nodeById, updateNode]);

  // ─────────────────────────────────────────────────────────────────
  // Cascade delete
  // ─────────────────────────────────────────────────────────────────
  const handleDeleteNode = useCallback((nodeId: string) => {
    const doomed = new Set<string>([nodeId]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const e of edges) {
        if (doomed.has(e.sourceId) && !doomed.has(e.targetId)) {
          doomed.add(e.targetId);
          changed = true;
        }
      }
    }
    doomed.forEach(id => removeNode(id));
    toast.push("info", "Node deleted", `Removed ${doomed.size} node${doomed.size !== 1 ? "s" : ""}.`);
  }, [edges, removeNode, toast]);

  // ─────────────────────────────────────────────────────────────────
  // Derived positions
  // ─────────────────────────────────────────────────────────────────
  const selectedScreenPos = selectedNode
    ? {
        x: selectedNode.position.x * viewport.zoom + viewport.x,
        y: selectedNode.position.y * viewport.zoom + viewport.y,
      }
    : { x: 0, y: 0 };

  const selectedHasChildren = selectedNode
    ? edges.some(e => e.sourceId === selectedNode.id)
    : false;

  // ─────────────────────────────────────────────────────────────────
  // Command palette actions
  // ─────────────────────────────────────────────────────────────────
  const paletteActions: PaletteAction[] = [
    { id: "new", group: "Investigate", icon: "sparkle", label: "New investigation", hint: "Add a seed", run: () => openModuleForm(null) },
    { id: "reset", group: "View", icon: "target", label: "Reset viewport", run: () => setViewport({ x: 0, y: 0, zoom: 1 }) },
    { id: "zoomin", group: "View", icon: "plus", label: "Zoom in", run: () => zoomTo(viewport.zoom * 1.15) },
    { id: "zoomout", group: "View", icon: "minus", label: "Zoom out", run: () => zoomTo(viewport.zoom * 0.85) },
    { id: "cards", group: "Panels", icon: "layout", label: "Toggle cards panel", run: () => { setShowCardList(v => !v); setShowChat(false); setShowLogPanel(false); } },
    { id: "chat", group: "Panels", icon: "sparkle", label: "Toggle AI chat", run: () => { setShowChat(v => !v); setShowCardList(false); setShowLogPanel(false); } },
    { id: "logs", group: "Panels", icon: "terminal", label: "Toggle live logs", run: () => { setShowLogPanel(v => !v); setShowChat(false); setShowCardList(false); } },
    { id: "theme", group: "Panels", icon: "palette", label: "Open theme panel", run: () => setShowTheme(true) },
    { id: "export", group: "Actions", icon: "upload", label: "Export / Save map", run: () => setShowExport(true) },
    { id: "config", group: "Actions", icon: "settings", label: "Open configuration", run: () => setShowConfig(true) },
    { id: "home", group: "Navigation", icon: "arrowLeft", label: "Back to home", run: () => navigate("/") },
  ];

  // ─────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────
  return (
    <div
      ref={canvasRef}
      id={CANVAS_ID}
      className="relative overflow-hidden select-none"
      style={{
        width: "100vw",
        height: "100vh",
        background: theme.canvasBackground,
      }}
    >
      <CanvasGrid viewport={viewport} width={size.w} height={size.h} />

      <svg
        className="absolute inset-0 w-full h-full"
        style={{ overflow: "visible" }}
        onWheel={onWheel}
      >
        {/* Shared paint servers — referenced by every GraphNode. */}
        <defs>
          <radialGradient id="node-glass" cx="50%" cy="30%">
            <stop offset="0%"   stopColor="#ffffff" stopOpacity="0.28" />
            <stop offset="55%"  stopColor="#ffffff" stopOpacity="0.05" />
            <stop offset="100%" stopColor="#ffffff" stopOpacity="0"    />
          </radialGradient>
        </defs>

        <rect
          x={0} y={0} width={size.w} height={size.h}
          fill="transparent"
          style={{ cursor: vpDragging.current ? "grabbing" : "grab" }}
          onPointerDown={onBgPointerDown}
          onPointerMove={onBgPointerMove}
          onPointerUp={onBgPointerUp}
        />

        {edges.map(edge => {
          const src = nodeById.get(edge.sourceId);
          const tgt = nodeById.get(edge.targetId);
          if (!src || !tgt) return null;
          const dimmed = !filteredIds.has(src.id) || !filteredIds.has(tgt.id);
          return (
            <EdgeLine
              key={edge.id}
              edge={edge}
              source={src}
              target={tgt}
              allNodes={nodes}
              viewport={viewport}
              dimmed={dimmed}
            />
          );
        })}

        {nodes.map(node => (
          <GraphNodeComp
            key={node.id}
            node={node}
            viewport={viewport}
            selected={node.id === selectedNode?.id}
            highlighted={node.id === highlightedNodeId}
            dimmed={!filteredIds.has(node.id)}
            compact={compactMode}
            onSelect={handleNodeSelect}
            onDragEnd={handleNodeDragEnd}
          />
        ))}
      </svg>

      {showPopup && selectedNode && (
        <NodePopup
          node={selectedNode}
          hasChildren={selectedHasChildren}
          screenPos={selectedScreenPos}
          onConnect={handleConnect}
          onViewDetails={handleViewDetails}
          onInvestigate={handleInvestigate}
          onColourChange={handleColourChange}
          onDelete={handleDeleteNode}
          onClose={() => setShowPopup(false)}
        />
      )}

      {showInfo && selectedNode && (
        <InfoCard
          node={selectedNode}
          initialPos={{
            x: Math.min(selectedScreenPos.x + 60, size.w - 400),
            y: Math.max(selectedScreenPos.y - 100, 10),
          }}
          onFieldChange={handleInfoFieldChange}
          onClose={() => setShowInfo(false)}
        />
      )}

      {moduleFormOpen && (
        <>
          <div
            className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm anim-in"
            onClick={() => setModuleFormOpen(false)}
          />
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div
              className="surface anim-pop w-full max-w-md p-6"
              onClick={e => e.stopPropagation()}
            >
              <div className="flex items-center justify-between mb-5">
                <div>
                  <p className="text-base font-bold text-white">
                    {moduleFormSelected
                      ? `${MODULE_LABELS[moduleFormSelected]} investigation`
                      : "Choose a module"}
                  </p>
                  <p className="text-[11px] text-zinc-500 mt-0.5">
                    Pick a data type, then enter the target.
                  </p>
                </div>
                <button
                  onClick={() => setModuleFormOpen(false)}
                  className="btn btn-ghost !p-1.5"
                >
                  <Icon name="close" size={14} />
                </button>
              </div>

              <div className="grid grid-cols-4 gap-2 mb-5">
                {MODULE_INPUTS.map(m => {
                  const active = moduleFormSelected === m.id;
                  return (
                    <button
                      key={m.id}
                      onClick={() => {
                        setModuleFormSelected(m.id);
                        setModuleFormError("");
                      }}
                      className={[
                        "flex flex-col items-center gap-1.5 rounded-xl border py-3 px-1",
                        "text-[10px] font-semibold transition-all",
                        active
                          ? "border-violet-500/60 bg-violet-500/15 text-violet-100 shadow-[0_0_0_1px_rgba(139,92,246,.35),0_8px_24px_-12px_rgba(139,92,246,.8)]"
                          : "border-edge-1 text-zinc-400 hover:border-edge-2 hover:text-zinc-100 hover:bg-white/[.02]",
                      ].join(" ")}
                    >
                      <Icon name={m.icon} size={16} />
                      <span>{m.label}</span>
                    </button>
                  );
                })}
              </div>

              {moduleFormSelected && (
                <div className="mb-4">
                  <label className="eyebrow block mb-1.5">
                    {MODULE_INPUTS.find(m => m.id === moduleFormSelected)?.label} target
                  </label>
                  <input
                    autoFocus
                    type={MODULE_INPUTS.find(m => m.id === moduleFormSelected)?.inputType ?? "text"}
                    placeholder={MODULE_INPUTS.find(m => m.id === moduleFormSelected)?.placeholder}
                    value={moduleFormInput}
                    onChange={e => {
                      setModuleFormInput(e.target.value);
                      if (e.target.value.trim()) {
                        const { module } = classifyInput(e.target.value.trim());
                        setModuleFormSelected(module);
                      }
                    }}
                    onKeyDown={e => e.key === "Enter" && handleModuleFormSubmit()}
                    className="field"
                  />
                </div>
              )}

              {moduleFormError && (
                <p className="text-[11px] text-rose-400 mb-3 flex items-center gap-1.5">
                  <Icon name="alert" size={11} />
                  {moduleFormError}
                </p>
              )}

              <div className="flex gap-2">
                <button
                  onClick={handleModuleFormSubmit}
                  disabled={!moduleFormSelected || !moduleFormInput.trim()}
                  className="flex-1 btn btn-primary justify-center !py-2.5"
                >
                  <Icon name="play" size={12} /> Start investigation
                </button>
                <button
                  onClick={() => setModuleFormOpen(false)}
                  className="btn !px-4"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Left toolbar */}
      <div className="absolute top-4 left-4 z-10 flex items-center gap-2 flex-wrap">
        <button onClick={() => navigate("/")} className="btn">
          <Icon name="arrowLeft" size={14} /> Home
        </button>

        <div className="surface flex items-center !rounded-xl overflow-hidden">
          <button
            onClick={() => zoomTo(viewport.zoom * 0.85)}
            className="px-3 py-2 text-zinc-400 hover:text-white hover:bg-white/5 transition-colors"
            aria-label="Zoom out"
          >
            <Icon name="minus" size={14} />
          </button>
          <button
            onClick={() => setViewport({ x: 0, y: 0, zoom: 1 })}
            className="px-3 py-2 text-[11px] font-mono text-zinc-400 hover:text-white
                       hover:bg-white/5 transition-colors tabular-nums min-w-[54px]"
            title="Reset viewport"
          >
            {Math.round(viewport.zoom * 100)}%
          </button>
          <button
            onClick={() => zoomTo(viewport.zoom * 1.15)}
            className="px-3 py-2 text-zinc-400 hover:text-white hover:bg-white/5 transition-colors"
            aria-label="Zoom in"
          >
            <Icon name="plus" size={14} />
          </button>
        </div>

        <div className="surface !rounded-xl px-3 py-2 text-[11px] text-zinc-400">
          <span className="tabular-nums">{nodes.length}</span>
          <span className="text-zinc-600 mx-1">·</span>
          <span className="tabular-nums">{edges.length}</span>
        </div>

        <button
          onClick={() => setPaletteOpen(true)}
          className="btn"
          title="Command palette (⌘K)"
        >
          <Icon name="command" size={13} /> Commands
          <span className="kbd ml-1">⌘K</span>
        </button>
      </div>

      {/* Right toolbar */}
      <div
        className="absolute top-4 z-10 flex items-center gap-2"
        style={{ right: rightPanelWidth + 16 }}
      >
        <ToolbarTab
          active={showCardList}
          icon="layout"
          label="Cards"
          onClick={() => {
            setShowCardList(v => !v);
            setShowChat(false);
            setShowLogPanel(false);
          }}
        />
        <ToolbarTab
          active={showChat}
          icon="sparkle"
          label="AI Chat"
          onClick={() => {
            setShowChat(v => !v);
            setShowLogPanel(false);
            setShowCardList(false);
          }}
        />
        <button onClick={() => setShowExport(true)} className="btn">
          <Icon name="upload" size={13} /> Export
        </button>
        <button onClick={() => setShowTheme(true)} className="btn">
          <Icon name="palette" size={13} /> Theme
        </button>
        <button onClick={() => setShowConfig(true)} className="btn">
          <Icon name="settings" size={13} /> Config
        </button>
      </div>

      {/* Filter panel */}
      <div
        className="absolute top-16 z-10"
        style={{ right: rightPanelWidth + 16 }}
      >
        <FilterPanel nodeCount={nodes.length} />
      </div>

      {/* Side panels */}
      <LiveLogPanel
        logs={logs}
        isOpen={showLogPanel && !showChat && !showCardList}
        onToggle={() => {
          setShowLogPanel(v => !v);
          setShowChat(false);
          setShowCardList(false);
        }}
        currentStage={currentStage}
      />
      <ChatPanel
        isOpen={showChat}
        onClose={() => setShowChat(false)}
        nodes={nodes}
        edges={edges}
      />
      <CardListPanel
        nodes={nodes}
        onSelectNode={focusNode}
        onClose={() => setShowCardList(false)}
        isOpen={showCardList}
      />

      {/* Modals */}
      <CanvasConfigPanel
        isOpen={showConfig}
        onClose={() => setShowConfig(false)}
      />
      <ThemePanel
        isOpen={showTheme}
        onClose={() => setShowTheme(false)}
      />
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        actions={paletteActions}
      />
      {showExport && (
        <ExportModal
          nodes={nodes}
          edges={edges}
          viewport={viewport}
          canvasElementId={CANVAS_ID}
          onClose={() => setShowExport(false)}
        />
      )}

      {/* Empty state */}
      {nodes.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="text-center anim-rise">
            <div className="relative mx-auto mb-6 h-24 w-24">
              <div className="absolute inset-0 rounded-full border border-dashed border-violet-500/40" />
              <div className="absolute inset-0 flex items-center justify-center">
                <div
                  className="h-16 w-16 rounded-full
                             bg-gradient-to-br from-violet-500/30 to-fuchsia-500/20
                             border border-violet-500/40 flex items-center justify-center
                             text-violet-200 animate-float-slow"
                >
                  <Icon name="sparkle" size={26} />
                </div>
              </div>
            </div>
            <p className="text-sm font-semibold text-zinc-300 mb-1">
              Nothing on the canvas yet
            </p>
            <p className="text-[11px] text-zinc-500 mb-5 max-w-xs mx-auto leading-relaxed">
              Press <span className="kbd mx-0.5">⌘K</span> and choose
              <span className="text-violet-300"> New investigation</span> to begin.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function ToolbarTab({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: IconName;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={[
        "btn",
        active
          ? "!border-violet-500/50 !bg-violet-500/15 !text-violet-100 " +
            "shadow-[0_0_0_1px_rgba(139,92,246,.35),0_8px_24px_-12px_rgba(139,92,246,.8)]"
          : "",
      ].join(" ")}
    >
      <Icon name={icon} size={13} /> {label}
    </button>
  );
}