// src/components/Layout.tsx
import React from "react";
import { NavLink, Outlet } from "react-router-dom";
import { Icon, type IconName } from "./Icons";

const NAV_ITEMS: Array<{ to: string; label: string; icon: IconName; hide?: boolean }> = [
  { to: "/",        label: "Investigate", icon: "search"   },
  { to: "/live",    label: "Live",        icon: "activity", hide: true },
  { to: "/history", label: "History",     icon: "refresh"  },
  { to: "/config",  label: "Config",      icon: "settings" },
];

export default function Layout() {
  return (
    <div className="flex h-screen overflow-hidden bg-ink-950 text-zinc-200 font-sans">
      {/* ── Sidebar ──────────────────────────────────────────────── */}
      <nav className="w-56 shrink-0 flex flex-col gap-1 border-r border-edge-0
                      bg-ink-900/80 backdrop-blur-xl p-4">
        <div className="mb-5 px-2">
          <p className="text-base font-black tracking-tight text-white
                        bg-gradient-to-br from-white to-zinc-400 bg-clip-text text-transparent">
            WhoCord
          </p>
          <p className="text-[10px] text-zinc-600 mt-0.5">OSINT Canvas v1.2</p>
        </div>

        {NAV_ITEMS.filter(n => !n.hide).map(item => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              [
                "rounded-lg px-3 py-2 text-[13px] transition-all",
                "flex items-center gap-2.5",
                isActive
                  ? "bg-violet-500/15 text-violet-100 border border-violet-500/40 font-semibold shadow-[0_0_0_1px_rgba(139,92,246,.2),0_8px_24px_-12px_rgba(139,92,246,.8)]"
                  : "text-zinc-400 hover:bg-white/[.04] hover:text-white border border-transparent",
              ].join(" ")
            }
          >
            <Icon name={item.icon} size={14} />
            <span>{item.label}</span>
          </NavLink>
        ))}

        <div className="mt-auto space-y-2">
          <button
            onClick={async () => {
              if (confirm("Shut down WhoCord server?")) {
                await fetch("/shutdown", { method: "POST" }).catch(() => {});
                setTimeout(() => window.close(), 400);
              }
            }}
            className="w-full rounded-lg px-3 py-2 text-[13px] text-rose-400
                       hover:bg-rose-500/10 transition-colors
                       flex items-center gap-2.5 text-left"
          >
            <Icon name="stop" size={12} />
            <span>Shut down</span>
          </button>
          <p className="text-center text-[10px] text-zinc-700">WhoCord v1.2</p>
        </div>
      </nav>

      {/* ── Main ─────────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}