// src/components/CanvasConfigPanel.tsx
import React, { useEffect, useRef, useState } from "react";
import {
  fetchConfig,
  savePivotConfig,
  setToken,
  toggleDebug,
  toggleTool,
  upgradeToolsUrl,
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

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

// ── Toggle ───────────────────────────────────────────────────────────
interface ToggleProps {
  on: boolean;
  onToggle: () => void;
  label: string;
  sublabel?: string;
}

function Toggle({ on, onToggle, label, sublabel }: ToggleProps) {
  return (
    <label className="flex items-center gap-3 cursor-pointer">
      <div
        onClick={onToggle}
        className={`relative w-9 h-5 rounded-full transition-colors shrink-0 ${
          on ? "bg-violet-600" : "bg-edge-2"
        }`}
      >
        <div
          className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white
                      transition-transform ${on ? "translate-x-4" : ""}`}
        />
      </div>
      <div className="flex-1">
        <span className="text-[13px] text-zinc-200">{label}</span>
        {sublabel && <p className="text-[11px] text-zinc-500">{sublabel}</p>}
      </div>
      <span
        className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
          on ? "bg-violet-500/15 text-violet-200" : "bg-white/[.03] text-zinc-500"
        }`}
      >
        {on ? "ON" : "OFF"}
      </span>
    </label>
  );
}

export default function CanvasConfigPanel({ isOpen, onClose }: Props) {
  const [cfg,        setCfg]        = useState<AppConfig | null>(null);
  const [loading,    setLoading]    = useState(true);
  const [tokenInputs, setTI]        = useState<Record<string, string>>({});
  const [saveMsg,    setSaveMsg]    = useState("");
  const [pivot,      setPivot]      = useState<PivotConfig>(DEFAULT_PIVOT);
  const [pivotSaved, setPivotSaved] = useState(false);
  const [upgradeLog, setLog]        = useState<string[]>([]);
  const [upgrading,  setUpgrading]  = useState(false);
  const logEndRef = useRef<HTMLDivElement>(null);

  const load = async () => {
    setLoading(true);
    try {
      const data = await fetchConfig();
      setCfg(data);
      setPivot(data.pivot ?? DEFAULT_PIVOT);
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  if (!isOpen) return null;

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

  const handleUpgrade = async () => {
    setLog([]);
    setUpgrading(true);
    try {
      const res    = await fetch(upgradeToolsUrl(), { method: "POST" });
      const reader = res.body?.getReader();
      const dec    = new TextDecoder();
      if (!reader) {
        setLog(["Upgrade stream unavailable."]);
        setUpgrading(false);
        return;
      }
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = dec.decode(value, { stream: true });
        for (const raw of chunk.split("\n")) {
          if (!raw.startsWith("data:")) continue;
          const text = raw.slice(5).trim();
          try {
            const evt = JSON.parse(text) as {
              type: string;
              payload: { line?: string; message?: string };
            };
            const line = evt.payload?.line ?? evt.payload?.message ?? "";
            if (line) {
              setLog(prev => [...prev, line]);
              requestAnimationFrame(() =>
                logEndRef.current?.scrollIntoView({ behavior: "smooth" }),
              );
            }
          } catch {
            if (text) setLog(prev => [...prev, text]);
          }
        }
      }
    } catch (err) {
      setLog(prev => [...prev, `Error: ${err}`]);
    } finally {
      setUpgrading(false);
    }
  };

  const TOKEN_LABELS: Record<string, string> = {
    DISCORD_TOKEN:     "Discord Token",
    GITHUB_TOKEN:      "GitHub Token",
    GROQ_API_KEY:      "Groq API Key",
    INSTAGRAM_SESSION: "Instagram Session",
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm anim-in"
        onClick={onClose}
      />

      {/* Centering wrapper — the animation runs on the inner panel,
          so its keyframe can't clobber a centering transform. */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
        <div
          className="surface anim-pop flex flex-col pointer-events-auto w-full"
          style={{ maxWidth: "min(720px, 96vw)", maxHeight: "86vh" }}
          onClick={e => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4
                          border-b border-edge-0 shrink-0">
            <div className="flex items-center gap-2.5">
              <span className="text-violet-300">
                <Icon name="settings" size={16} />
              </span>
              <h2 className="text-base font-bold text-white">Configuration</h2>
            </div>
            <button onClick={onClose} className="btn btn-ghost !p-1.5">
              <Icon name="close" size={14} />
            </button>
          </div>

          {loading && (
            <div className="flex-1 flex items-center justify-center text-zinc-500 text-sm py-12">
              Loading config…
            </div>
          )}

          {!loading && (
            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-8">
              {/* API Tokens */}
              <section>
                <h3 className="text-[13px] font-bold text-white mb-3 flex items-center gap-2">
                  <Icon name="key" size={14} className="text-violet-300" />
                  API Tokens
                </h3>
                <div className="space-y-3">
                  {cfg && Object.entries(TOKEN_LABELS).map(([key, label]) => (
                    <div key={key}>
                      <label className="flex items-center justify-between text-[11px] text-zinc-500 mb-1">
                        <span>{label}</span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            cfg.tokens[key as keyof typeof cfg.tokens]
                              ? "bg-emerald-500/15 text-emerald-300"
                              : "bg-white/[.03] text-zinc-500"
                          }`}
                        >
                          {cfg.tokens[key as keyof typeof cfg.tokens] ? "set" : "not set"}
                        </span>
                      </label>
                      <input
                        type="password"
                        placeholder={`Enter ${label}…`}
                        value={tokenInputs[key] ?? ""}
                        onChange={e =>
                          setTI(p => ({ ...p, [key]: e.target.value }))
                        }
                        className="field !py-1.5 !text-sm"
                      />
                    </div>
                  ))}
                </div>
                <div className="flex items-center gap-3 mt-3">
                  <button onClick={handleSaveTokens} className="btn btn-primary">
                    <Icon name="check" size={12} /> Save tokens
                  </button>
                  {saveMsg && (
                    <span className="text-[12px] text-emerald-400">{saveMsg}</span>
                  )}
                </div>
              </section>

              {/* Debug */}
              {cfg && (
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
              )}

              {/* Pivoting */}
              <section>
                <h3 className="text-[13px] font-bold text-white mb-1 flex items-center gap-2">
                  <Icon name="refresh" size={14} className="text-violet-300" />
                  Adaptive Pivoting
                  <span
                    className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                      pivot.enabled
                        ? "bg-emerald-500/15 text-emerald-300"
                        : "bg-white/[.03] text-zinc-500"
                    }`}
                  >
                    {pivot.enabled ? "ENABLED" : "DISABLED"}
                  </span>
                </h3>
                <p className="text-[11px] text-zinc-500 mb-4">
                  Automatically investigate discovered emails and usernames.
                </p>

                <div className="space-y-4">
                  <Toggle
                    on={pivot.enabled}
                    onToggle={() => setPivot(p => ({ ...p, enabled: !p.enabled }))}
                    label="Enable pivoting"
                  />

                  {pivot.enabled && (
                    <div className="ml-4 pl-4 border-l-2 border-violet-500/20 space-y-3">
                      <Toggle
                        on={pivot.pivot_email}
                        onToggle={() =>
                          setPivot(p => ({ ...p, pivot_email: !p.pivot_email }))
                        }
                        label="Pivot on emails"
                      />
                      <Toggle
                        on={pivot.pivot_username}
                        onToggle={() =>
                          setPivot(p => ({ ...p, pivot_username: !p.pivot_username }))
                        }
                        label="Pivot on usernames"
                      />
                      <div>
                        <label className="flex justify-between text-[11px] text-zinc-500 mb-1">
                          <span>Max recursion depth</span>
                          <span className="font-bold text-white">{pivot.max_depth}</span>
                        </label>
                        <input
                          type="range"
                          min={1}
                          max={5}
                          step={1}
                          value={pivot.max_depth}
                          onChange={e =>
                            setPivot(p => ({ ...p, max_depth: Number(e.target.value) }))
                          }
                          className="w-full accent-violet-500"
                        />
                      </div>
                      <div>
                        <label className="flex justify-between text-[11px] text-zinc-500 mb-1">
                          <span>Max seeds per depth</span>
                          <span className="font-bold text-white">{pivot.max_seeds}</span>
                        </label>
                        <input
                          type="range"
                          min={1}
                          max={20}
                          step={1}
                          value={pivot.max_seeds}
                          onChange={e =>
                            setPivot(p => ({ ...p, max_seeds: Number(e.target.value) }))
                          }
                          className="w-full accent-violet-500"
                        />
                      </div>
                      <Toggle
                        on={pivot.require_confirm}
                        onToggle={() =>
                          setPivot(p => ({
                            ...p,
                            require_confirm: !p.require_confirm,
                          }))
                        }
                        label="Confirm before each pivot"
                      />
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-3 mt-4">
                  <button onClick={handleSavePivot} className="btn btn-primary">
                    <Icon name="check" size={12} /> Save pivot settings
                  </button>
                  {pivotSaved && (
                    <span className="text-[12px] text-emerald-400">Saved</span>
                  )}
                </div>
              </section>

              {/* Tools */}
              {cfg && (
                <section>
                  <h3 className="text-[13px] font-bold text-white mb-3 flex items-center gap-2">
                    <Icon name="server" size={14} className="text-violet-300" />
                    Tools
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
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
                          <div
                            className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white
                                        transition-transform ${
                                          tool.enabled ? "translate-x-4" : ""
                                        }`}
                          />
                        </div>
                      </label>
                    ))}
                  </div>
                </section>
              )}

              {/* Upgrade */}
              <section>
                <h3 className="text-[13px] font-bold text-white mb-2 flex items-center gap-2">
                  <Icon name="upload" size={14} className="text-violet-300" />
                  Upgrade external tools
                </h3>
                <p className="text-[11px] text-zinc-500 mb-3">
                  Upgrades all pip-installable OSINT tools via the server.
                </p>
                <button
                  onClick={handleUpgrade}
                  disabled={upgrading}
                  className="btn"
                >
                  <Icon name="refresh" size={12} />
                  {upgrading ? "Upgrading…" : "Run upgrade"}
                </button>
                {upgradeLog.length > 0 && (
                  <div
                    className="mt-3 rounded-lg bg-ink-950 border border-edge-0
                               p-3 max-h-40 overflow-y-auto font-mono text-[10px]
                               text-zinc-400 space-y-0.5"
                  >
                    {upgradeLog.map((line, i) => (
                      <div key={i}>{line}</div>
                    ))}
                    <div ref={logEndRef} />
                  </div>
                )}
              </section>
            </div>
          )}
        </div>
      </div>
    </>
  );
}