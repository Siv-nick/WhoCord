// src/pages/StartPage.tsx
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useGraphState, newNodeId } from "../hooks/useGraphState";
import { openMapFilePicker } from "../utils/export";
import { Icon, type IconName } from "../components/Icons";
import type { GraphNode } from "../types/graph";

const FEATURES: Array<{ icon: IconName; title: string; text: string }> = [
  { icon: "brain",    title: "Intelligence Engine", text: "Correlations, graph analytics, and AI narrative." },
  { icon: "activity", title: "Live Graph",          text: "Watch every finding expand the map in real time." },
  { icon: "refresh",  title: "Adaptive Pivoting",   text: "Follow emails and usernames recursively." },
  { icon: "server",   title: "20+ Integrations",    text: "Holehe, GHunt, HIBP, WhatsMyName and more." },
];

export default function StartPage() {
  const navigate              = useNavigate();
  const { loadMap, clearMap } = useGraphState();
  const [loadError, setErr]   = useState("");
  const [loading,   setLoad]  = useState(false);
  const [mounted,   setMnt]   = useState(false);

  useEffect(() => { requestAnimationFrame(() => setMnt(true)); }, []);

  const handleNew = () => {
    clearMap();
    const rootNode: GraphNode = {
      id: newNodeId(), label: "Start here", entityType: "unknown",
      module: "root", position: { x: 0, y: 0 }, colour: "#ffffff",
      investigating: false, progress: 0, infoFields: [], rawData: {},
      createdAt: Date.now(),
    };
    navigate("/canvas", { state: { rootNode } });
  };

  const handleLoad = async () => {
    setErr(""); setLoad(true);
    try {
      const { nodes, edges, viewport } = await openMapFilePicker();
      loadMap(nodes, edges, viewport);
      navigate("/canvas");
    } catch (e) { setErr(String(e)); }
    finally { setLoad(false); }
  };

  return (
    <div className="relative min-h-screen overflow-hidden flex flex-col items-center justify-center px-6 py-16">
      {/* Ambient orbs */}
      <div aria-hidden className="pointer-events-none absolute inset-0 -z-10">
        <div className="absolute -top-40 -left-32 h-[520px] w-[520px] rounded-full
                        bg-violet-600/20 blur-[140px] animate-float-slow" />
        <div className="absolute -bottom-32 -right-24 h-[420px] w-[420px] rounded-full
                        bg-cyan-500/15 blur-[140px] animate-float-slow"
             style={{ animationDelay: "2s" }} />
        <div className="absolute top-1/3 left-1/2 h-[380px] w-[380px] rounded-full
                        bg-emerald-500/10 blur-[140px] animate-float-slow"
             style={{ animationDelay: "4s" }} />
      </div>

      {/* Hero */}
      <div className={`text-center mb-14 transition-all duration-700 ${mounted ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4"}`}>
        <div className="inline-flex items-center gap-2 mb-6 chip chip-violet">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full rounded-full bg-violet-400 opacity-75 animate-ping" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-violet-400" />
          </span>
          WhoCord v1.2
        </div>

        <h1
          className="text-6xl md:text-7xl font-black tracking-tighter mb-4
                     bg-gradient-to-br from-white via-zinc-200 to-zinc-500
                     bg-clip-text text-transparent"
          style={{ letterSpacing: "-0.045em" }}
        >
          WhoCord
        </h1>

        <p className="text-zinc-400 text-base max-w-md mx-auto leading-relaxed">
          An interactive OSINT canvas that grows with every discovery.
          Start with a seed, watch the map build itself.
        </p>
      </div>

      {/* Action cards */}
      <div className={`w-full max-w-3xl grid grid-cols-1 md:grid-cols-2 gap-4 transition-all duration-700 delay-100 ${mounted ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4"}`}>
        <ActionCard
          icon="sparkle"
          badge="New"
          title="Blank canvas"
          subtitle="Start a fresh investigation from a single seed."
          cta="Start investigating"
          onClick={handleNew}
          variant="primary"
        />
        <ActionCard
          icon="download"
          badge={loading ? "Loading…" : "Restore"}
          title="Load saved map"
          subtitle="Open a .whocord-map file — nodes, edges and viewport preserved."
          cta="Open file"
          onClick={handleLoad}
          disabled={loading}
          variant="secondary"
        />
      </div>

      {loadError && (
        <div className="mt-6 anim-pop max-w-md rounded-xl border border-rose-500/30
                        bg-rose-500/10 px-4 py-2.5 text-sm text-rose-300">
          {loadError}
        </div>
      )}

      {/* Feature grid */}
      <div className={`mt-16 w-full max-w-3xl grid grid-cols-2 md:grid-cols-4 gap-3 transition-all duration-700 delay-200 ${mounted ? "opacity-100 translate-y-0" : "opacity-0 translate-y-4"}`}>
        {FEATURES.map(f => (
          <div key={f.title}
               className="rounded-xl border border-edge-1 bg-ink-800/50 px-4 py-3.5
                          backdrop-blur-sm hover:border-edge-2 transition-colors">
            <div className="mb-2 text-violet-300">
              <Icon name={f.icon} size={18} />
            </div>
            <div className="text-xs font-semibold text-zinc-200 mb-0.5">{f.title}</div>
            <div className="text-[10px] leading-relaxed text-zinc-500">{f.text}</div>
          </div>
        ))}
      </div>

      <a href="/dashboard"
         className="mt-14 text-[11px] text-zinc-600 hover:text-zinc-300 underline-offset-4
                    hover:underline transition-colors">
        Open legacy dashboard →
      </a>
    </div>
  );
}

function ActionCard({
  icon, badge, title, subtitle, cta, onClick, disabled, variant,
}: {
  icon: IconName;
  badge: string;
  title: string;
  subtitle: string;
  cta: string;
  onClick: () => void;
  disabled?: boolean;
  variant: "primary" | "secondary";
}) {
  const isPrimary = variant === "primary";
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={[
        "group relative text-left rounded-2xl border p-6 overflow-hidden",
        "transition-all duration-300 disabled:opacity-60 disabled:cursor-not-allowed",
        isPrimary
          ? "border-violet-500/30 bg-gradient-to-br from-violet-600/10 via-ink-800 to-ink-850 hover:border-violet-400/60 hover:shadow-[0_24px_60px_-24px_rgba(139,92,246,.8)]"
          : "border-edge-1 bg-ink-800/70 hover:border-edge-2 hover:shadow-float",
      ].join(" ")}
    >
      {/* Hover sheen */}
      <span aria-hidden
        className="pointer-events-none absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
        style={{
          background: isPrimary
            ? "radial-gradient(500px 200px at 30% 0%, rgba(139,92,246,.22), transparent 70%)"
            : "radial-gradient(500px 200px at 30% 0%, rgba(255,255,255,.05), transparent 70%)",
        }} />

      <div className="relative">
        <div className="flex items-center justify-between mb-5">
          <div className={`flex h-10 w-10 items-center justify-center rounded-xl
                          ${isPrimary
                            ? "bg-violet-500/20 text-violet-300 border border-violet-400/30"
                            : "bg-white/5 text-zinc-300 border border-edge-1"}`}>
            <Icon name={icon} size={18} />
          </div>
          <span className={`text-[10px] font-bold uppercase tracking-wider
                          ${isPrimary ? "text-violet-300/80" : "text-zinc-500"}`}>
            {badge}
          </span>
        </div>

        <h2 className="text-lg font-bold text-white mb-1.5">{title}</h2>
        <p className="text-sm text-zinc-400 leading-relaxed mb-5">{subtitle}</p>

        <div className={`inline-flex items-center gap-2 text-xs font-bold
                        ${isPrimary ? "text-violet-300" : "text-zinc-300"}`}>
          {cta}
          <span className="transition-transform group-hover:translate-x-1">→</span>
        </div>
      </div>
    </button>
  );
}