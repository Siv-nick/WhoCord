// src/components/ModuleCard.tsx
import React from "react";
import type { ModuleMeta } from "../types/investigation";
import { Icon } from "./Icons";

interface Props {
  module:       ModuleMeta;
  onClick:      (module: ModuleMeta) => void;
  isActive?:    boolean;
  extraColors?: Record<string, { border: string; hover: string; badge: string }>;
}

const BASE_COLOR_STYLES: Record<string, { border: string; hover: string; badge: string }> = {
  indigo:  { border: "border-indigo-500/40",  hover: "hover:border-indigo-400",  badge: "bg-indigo-500/15 text-indigo-300"  },
  sky:     { border: "border-sky-500/40",     hover: "hover:border-sky-400",     badge: "bg-sky-500/15 text-sky-300"        },
  violet:  { border: "border-violet-500/40",  hover: "hover:border-violet-400",  badge: "bg-violet-500/15 text-violet-300"  },
  emerald: { border: "border-emerald-500/40", hover: "hover:border-emerald-400", badge: "bg-emerald-500/15 text-emerald-300"},
  amber:   { border: "border-amber-500/40",   hover: "hover:border-amber-400",   badge: "bg-amber-500/15 text-amber-300"    },
  rose:    { border: "border-rose-500/40",    hover: "hover:border-rose-400",    badge: "bg-rose-500/15 text-rose-300"      },
  teal:    { border: "border-teal-500/40",    hover: "hover:border-teal-400",    badge: "bg-teal-500/15 text-teal-300"      },
  green:   { border: "border-green-500/40",   hover: "hover:border-green-400",   badge: "bg-green-500/15 text-green-300"    },
};

export default function ModuleCard({
  module, onClick, isActive = false, extraColors = {},
}: Props) {
  const palette = { ...BASE_COLOR_STYLES, ...extraColors };
  const styles  = palette[module.color] ?? palette.indigo;

  return (
    <button
      onClick={() => onClick(module)}
      className={[
        "group rounded-xl border bg-ink-850 p-4 text-left w-full",
        "transition-all duration-200 cursor-pointer",
        styles.border, styles.hover,
        isActive
          ? "ring-2 ring-offset-1 ring-offset-ink-950 ring-violet-500 bg-ink-800"
          : "hover:bg-ink-800 hover:shadow-[0_20px_44px_-20px_rgba(0,0,0,.7)]",
      ].join(" ")}
    >
      <div className={`h-10 w-10 rounded-xl border flex items-center justify-center
                       ${styles.border} bg-white/[.02] mb-3
                       group-hover:bg-white/[.05] transition-colors`}>
        <Icon name={module.icon} size={18} />
      </div>

      <h3 className="text-sm font-semibold text-white mb-1 leading-tight">
        {module.title}
      </h3>
      <p className="text-[11px] text-zinc-500 leading-relaxed mb-3 line-clamp-2">
        {module.description}
      </p>

      <span className={`text-[10px] font-bold px-2 py-0.5 rounded
                        uppercase tracking-wider ${styles.badge}`}>
        {isActive ? "Selected" : "Launch"}
      </span>
    </button>
  );
}