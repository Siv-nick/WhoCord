// src/pages/Config.tsx
import React, { useRef, useState } from "react";
import CanvasConfigPanel from "../components/CanvasConfigPanel";
import { Icon } from "../components/Icons";
import { upgradeToolsUrl, shutdownServer } from "../utils/api";

export default function Config() {
  const [upgradeLog, setLog]      = useState<string[]>([]);
  const [upgrading, setUpgrading] = useState(false);
  const logEndRef                 = useRef<HTMLDivElement>(null);
  const [showConfig, setShowConfig] = useState(true);

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

  const handleShutdown = async () => {
    if (!confirm("Shut down the WhoCord server?")) return;
    await shutdownServer();
    setTimeout(() => window.close(), 500);
  };

  return (
    <div className="p-6 max-w-3xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white">Configuration</h1>
        <p className="text-[13px] text-zinc-500 mt-0.5">
          Manage API keys, tool toggles, and server options.
        </p>
      </div>

      {/* Config panel — opens inline */}
      <div className="surface p-5 mb-6">
        <CanvasConfigPanel
          isOpen={showConfig}
          onClose={() => setShowConfig(false)}
        />
        {!showConfig && (
          <button onClick={() => setShowConfig(true)} className="btn btn-primary">
            <Icon name="settings" size={12} /> Open configuration
          </button>
        )}
      </div>

      {/* Upgrade tools */}
      <div className="surface p-5 mb-6">
        <h2 className="text-[13px] font-bold text-white mb-2 flex items-center gap-2">
          <Icon name="upload" size={14} className="text-violet-300" />
          Upgrade external tools
        </h2>
        <p className="text-[11px] text-zinc-500 mb-3">
          Upgrades all pip-installable OSINT tools (Sherlock, Maigret, Holehe…).
          External tools (Scylla, PhoneInfoga) must be upgraded manually.
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
          <div className="mt-4 rounded-lg bg-ink-950 border border-edge-0
                          p-3 max-h-48 overflow-y-auto font-mono text-[11px]
                          text-zinc-400 space-y-0.5">
            {upgradeLog.map((line, i) => <div key={i}>{line}</div>)}
            <div ref={logEndRef} />
          </div>
        )}
      </div>

      {/* Danger zone */}
      <div className="surface p-5 border-rose-500/20">
        <h2 className="text-[13px] font-bold text-rose-400 mb-2 flex items-center gap-2">
          <Icon name="alert" size={14} />
          Danger Zone
        </h2>
        <p className="text-[11px] text-zinc-500 mb-3">
          Shuts down the Flask process entirely. You will need to restart WhoCord manually.
        </p>
        <button onClick={handleShutdown} className="btn btn-danger">
          <Icon name="stop" size={12} /> Shut Down Server
        </button>
      </div>
    </div>
  );
}