// src/components/ConfigPanel.tsx
// Legacy config panel — kept for the /dashboard/config route.
// The canvas uses CanvasConfigPanel instead.

import React, { useEffect, useState } from "react";
import {
  fetchConfig,
  savePivotConfig,
  setToken,
  toggleDebug,
  toggleTool,
} from "../utils/api";
import type { AppConfig, PivotConfig, ToolConfig } from "../types/investigation";
import { Icon } from "./Icons";

const DEFAULT_PIVOT: PivotConfig = {
  enabled:         false,
  pivot_email:     true,
  pivot_username:  true,
  max_depth:       3,
  max_seeds:       5,
  require_confirm: false,
};

interface ToggleProps {
  on:        boolean;
  onToggle:  () => void;
  label:     string;
  sublabel?: string;
}

function Toggle({ on, onToggle, label, sublabel }: ToggleProps) {
  return (
    <label className="flex items-center gap-3 cursor-pointer">
      <div
        onClick={onToggle}
        className={`relative w-10 h-5 rounded-full transition-colors shrink-0 ${
          on ? "bg-violet-600" : "bg-edge-2"
        }`}
      >
        <div
          className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white
                      transition-transform ${on ? "translate-x-5" : ""}`}
        />
      </div>
      <div className="flex-1">
        <span className="text-[13px] text-zinc-200">{label}</span>
        {sublabel && <p className="text-[11px] text-zinc-500">{sublabel}</p>}
      </div>
      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
        on ? "bg-violet-500/15 text-violet-200" : "bg-white/[.03] text-zinc-500"
      }`}>
        {on ? "ON" : "OFF"}
      </span>
    </label>
  );
}

export default function ConfigPanel() {
  const [cfg, setCfg]               = useState<AppConfig | null>(null);
  const [loading, setLoading]       = useState(true);
  const [tokenInputs, setTI]        = useState<Record<string, string>>({});
  const [saveMsg, setSaveMsg]       = useState("");
  const [pivot, setPivot]           = useState<PivotConfig>(DEFAULT_PIVOT);
  const [pivotSaved, setPivotSaved] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const data = await fetchConfig();
      setCfg(data);
      setPivot(data.pivot ?? DEFAULT_PIVOT);
    } catch { /* ignore */ }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const handleSaveTokens = async () => {
    for (const [key, value] of Object.entries(tokenInputs)) {
      if (value.trim()) await setToken(key, value.trim());
    }
    setTI({});
    setSaveMsg("Saved");
    await load();
    setTimeout(() => setSaveMsg(""), 2500);
  };

  const handleToggleTool = async (tool: ToolConfig) => {
    await toggleTool(tool.key, !tool.enabled);
    await load();
  };

  const handleToggleDebug = async () => {
    await toggleDebug();
    await load();
  };

  const handleSavePivot = async () => {
    await savePivotConfig(pivot);
    setPivotSaved(true);
    setTimeout(() => setPivotSaved(false), 2500);
  };

  if (loading) return <div className="p-8 text-zinc-500 text-sm">Loading config…</div>;
  if (!cfg)    return <div className="p-8 text-rose-400 text-sm">Failed to load config.</div>;

  const TOKEN_LABELS: Record<string, string> = {
    DISCORD_TOKEN:     "Discord Token",
    GITHUB_TOKEN:      "GitHub Token",
    GROQ_API_KEY:      "Groq API Key",
    INSTAGRAM_SESSION: "Instagram Session",
  };

  return (
    <div className="space-y-6">
      {/* API Tokens */}
      <section>
        <h3 className="text-[13px] font-bold text-white mb-3 flex items-center gap-2">
          <Icon name="key" size={14} className="text-violet-300" />
          API Tokens
        </h3>
        <div className="space-y-3">
          {Object.entries(TOKEN_LABELS).map(([key, label]) => (
            <div key={key}>
              <label className="flex items-center justify-between text-[11px] text-zinc-500 mb-1">
                <span>{label}</span>
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                  cfg.tokens[key as keyof typeof cfg.tokens]
                    ? "bg-emerald-500/15 text-emerald-300"
                    : "bg-white/[.03] text-zinc-500"
                }`}>
                  {cfg.tokens[key as keyof typeof cfg.tokens] ? "set" : "not set"}
                </span>
              </label>
              <input
                type="password"
                placeholder={`Enter ${label}…`}
                value={tokenInputs[key] ?? ""}
                onChange={e => setTI(p => ({ ...p, [key]: e.target.value }))}
                className="field !py-1.5 !text-sm"
              />
            </div>
          ))}
        </div>
        <div className="flex items-center gap-3 mt-3">
          <button onClick={handleSaveTokens} className="btn btn-primary">
            <Icon name="check" size={12} /> Save tokens
          </button>
          {saveMsg && <span className="text-[12px] text-emerald-400">{saveMsg}</span>}
        </div>
      </section>

      {/* Debug */}
      <section>
        <h3 className="text-[13px] font-bold text-white mb-3 flex items-center gap-2">
          <Icon name="terminal" size={14} className="text-violet-300" />
          Debug
        </h3>
        <Toggle
          on={cfg.debug}
          onToggle={handleToggleDebug}
          label="Verbose logging"
          sublabel="Write detailed output to the Live Logs panel"
        />
      </section>

      {/* Pivoting */}
      <section>
        <h3 className="text-[13px] font-bold text-white mb-1 flex items-center gap-2">
          <Icon name="refresh" size={14} className="text-violet-300" />
          Adaptive Pivoting
          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
            pivot.enabled ? "bg-emerald-500/15 text-emerald-300" : "bg-white/[.03] text-zinc-500"
          }`}>
            {pivot.enabled ? "ENABLED" : "DISABLED"}
          </span>
        </h3>
        <p className="text-[11px] text-zinc-500 mb-4">
          Automatically investigate newly discovered emails and usernames during the investigation.
        </p>

        <div className="space-y-4">
          <Toggle
            on={pivot.enabled}
            onToggle={() => setPivot(p => ({ ...p, enabled: !p.enabled }))}
            label="Enable pivoting"
            sublabel="Follow discovered seeds in sub-investigations"
          />
          {pivot.enabled && (
            <>
              <div className="ml-3 pl-3 border-l-2 border-violet-500/20 space-y-3">
                <Toggle
                  on={pivot.pivot_email}
                  onToggle={() => setPivot(p => ({ ...p, pivot_email: !p.pivot_email }))}
                  label="Pivot on emails"
                  sublabel="Follow discovered email addresses"
                />
                <Toggle
                  on={pivot.pivot_username}
                  onToggle={() => setPivot(p => ({ ...p, pivot_username: !p.pivot_username }))}
                  label="Pivot on usernames"
                  sublabel="Follow discovered usernames and handles"
                />
              </div>

              <div>
                <label className="flex items-center justify-between text-[11px] text-zinc-500 mb-1.5">
                  <span>Max recursion depth</span>
                  <span className="font-bold text-white">{pivot.max_depth}</span>
                </label>
                <input
                  type="range" min={1} max={5} step={1}
                  value={pivot.max_depth}
                  onChange={e => setPivot(p => ({ ...p, max_depth: Number(e.target.value) }))}
                  className="w-full accent-violet-500"
                />
                <div className="flex justify-between text-[10px] text-zinc-600 mt-0.5">
                  <span>1 (shallow)</span>
                  <span>5 (deep)</span>
                </div>
              </div>

              <div>
                <label className="flex items-center justify-between text-[11px] text-zinc-500 mb-1.5">
                  <span>Max seeds per depth level</span>
                  <span className="font-bold text-white">{pivot.max_seeds}</span>
                </label>
                <input
                  type="range" min={1} max={20} step={1}
                  value={pivot.max_seeds}
                  onChange={e => setPivot(p => ({ ...p, max_seeds: Number(e.target.value) }))}
                  className="w-full accent-violet-500"
                />
                <div className="flex justify-between text-[10px] text-zinc-600 mt-0.5">
                  <span>1 (conservative)</span>
                  <span>20 (aggressive)</span>
                </div>
              </div>

              <Toggle
                on={pivot.require_confirm}
                onToggle={() => setPivot(p => ({ ...p, require_confirm: !p.require_confirm }))}
                label="Confirm before each pivot"
                sublabel="Pause and ask you to approve seeds before running"
              />
            </>
          )}
        </div>

        <div className="flex items-center gap-3 mt-4">
          <button onClick={handleSavePivot} className="btn btn-primary">
            <Icon name="check" size={12} /> Save pivot settings
          </button>
          {pivotSaved && <span className="text-[12px] text-emerald-400">Saved</span>}
        </div>
      </section>

      {/* Tools */}
      <section>
        <h3 className="text-[13px] font-bold text-white mb-3 flex items-center gap-2">
          <Icon name="server" size={14} className="text-violet-300" />
          Tools
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {cfg.tools.map(tool => (
            <label
              key={tool.key}
              className="flex items-center justify-between rounded-lg
                         border border-edge-1 bg-ink-800/50 px-3 py-2 cursor-pointer
                         hover:border-edge-2 transition-colors"
            >
              <span className="text-[11px] text-zinc-300">{tool.desc}</span>
              <div
                onClick={() => handleToggleTool(tool)}
                className={`relative w-8 h-4 rounded-full transition-colors shrink-0 ml-2 ${
                  tool.enabled ? "bg-violet-600" : "bg-edge-2"
                }`}
              >
                <div className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white
                                transition-transform ${tool.enabled ? "translate-x-4" : ""}`} />
              </div>
            </label>
          ))}
        </div>
      </section>
    </div>
  );
}