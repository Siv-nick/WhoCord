// src/components/CommandPalette.tsx
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Icon, type IconName } from "./Icons";

export interface PaletteAction {
  id: string;
  label: string;
  hint?: string;
  icon?: IconName;
  group: string;
  run: () => void;
}

interface Props {
  open: boolean;
  onClose: () => void;
  actions: PaletteAction[];
}

export default function CommandPalette({ open, onClose, actions }: Props) {
  const [q, setQ]     = useState("");
  const [sel, setSel] = useState(0);
  const inputRef      = useRef<HTMLInputElement>(null);
  const listRef       = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) {
      setQ("");
      setSel(0);
      setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [open]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return actions;
    return actions.filter(a =>
      a.label.toLowerCase().includes(needle) ||
      a.group.toLowerCase().includes(needle) ||
      (a.hint ?? "").toLowerCase().includes(needle),
    );
  }, [q, actions]);

  useEffect(() => {
    if (sel >= filtered.length) setSel(0);
  }, [filtered, sel]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape")    { e.preventDefault(); onClose(); }
      if (e.key === "ArrowDown") { e.preventDefault(); setSel(s => Math.min(s + 1, filtered.length - 1)); }
      if (e.key === "ArrowUp")   { e.preventDefault(); setSel(s => Math.max(s - 1, 0)); }
      if (e.key === "Enter")     {
        e.preventDefault();
        const a = filtered[sel];
        if (a) { a.run(); onClose(); }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, filtered, sel, onClose]);

  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-idx="${sel}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  if (!open) return null;

  // Grouped rendering
  const groups: Record<string, PaletteAction[]> = {};
  filtered.forEach(a => (groups[a.group] ??= []).push(a));
  let idx = -1;

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-[14vh]">
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm anim-in"
        onClick={onClose}
      />
      <div className="relative w-full max-w-xl mx-4 surface anim-pop overflow-hidden">
        {/* Input */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-edge-0">
          <span className="text-zinc-500">
            <Icon name="search" size={14} />
          </span>
          <input
            ref={inputRef}
            value={q}
            onChange={e => setQ(e.target.value)}
            placeholder="Search commands…"
            className="flex-1 bg-transparent text-sm text-zinc-100
                       placeholder-zinc-500 outline-none border-0"
          />
          <span className="kbd">esc</span>
        </div>

        {/* Results */}
        <div ref={listRef} className="max-h-[52vh] overflow-y-auto py-1.5">
          {filtered.length === 0 && (
            <p className="px-4 py-10 text-center text-sm text-zinc-500">
              No matching commands.
            </p>
          )}
          {Object.entries(groups).map(([group, items]) => (
            <div key={group} className="mb-1">
              <div className="px-4 pt-2 pb-1 eyebrow">{group}</div>
              {items.map(a => {
                idx += 1;
                const i      = idx;
                const active = i === sel;
                return (
                  <button
                    key={a.id}
                    data-idx={i}
                    onMouseEnter={() => setSel(i)}
                    onClick={() => { a.run(); onClose(); }}
                    className={[
                      "w-full flex items-center gap-3 px-4 py-2.5 text-left",
                      "transition-colors",
                      active
                        ? "bg-violet-500/15 text-white"
                        : "text-zinc-300 hover:bg-white/[.03]",
                    ].join(" ")}
                  >
                    <span className={`w-6 flex justify-center ${
                      active ? "text-violet-300" : "text-zinc-400"
                    }`}>
                      <Icon name={a.icon ?? "play"} size={14} />
                    </span>
                    <span className="flex-1 text-[13px] font-medium">{a.label}</span>
                    {a.hint && <span className="text-[11px] text-zinc-500">{a.hint}</span>}
                    {active && <span className="kbd">↵</span>}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}