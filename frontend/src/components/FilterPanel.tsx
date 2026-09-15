// src/components/FilterPanel.tsx
import React, { useState } from "react";
import type { NodeEntityType } from "../types/graph";
import { useGraphState } from "../hooks/useGraphState";
import { Icon, type IconName } from "./Icons";

const TYPES: Array<{ type: NodeEntityType; label: string; icon: IconName }> = [
  { type: "email",          label: "Emails",    icon: "mail"   },
  { type: "phone",          label: "Phones",    icon: "phone"  },
  { type: "social_profile", label: "Social",    icon: "users"  },
  { type: "username",       label: "Usernames", icon: "atSign" },
  { type: "domain",         label: "Domains",   icon: "globe"  },
  { type: "url",            label: "URLs",      icon: "link"   },
  { type: "breach",         label: "Breaches",  icon: "alert"  },
  { type: "image",          label: "Images",    icon: "image"  },
  { type: "ip",             label: "IPs",       icon: "server" },
  { type: "name",           label: "Names",     icon: "user"   },
  { type: "location",       label: "Locations", icon: "mapPin" },
  { type: "unknown",        label: "Other",     icon: "dot"    },
];

function FilterPanel({ nodeCount }: { nodeCount: number }) {
  const { filter, setTypeFilter, setSearchFilter, clearFilters } = useGraphState();
  const [open, setOpen] = useState(false);
  const allOn = TYPES.every(e => filter.types.has(e.type));

  const toggleAll = () => {
    const to = !allOn;
    TYPES.forEach(e => setTypeFilter(e.type, to));
  };

  return (
    <div className="select-none">
      <button
        onClick={() => setOpen(v => !v)}
        className="surface surface-hover !rounded-xl px-3 py-2 flex items-center gap-2"
      >
        <span className="text-zinc-400">
          <Icon name="search" size={13} />
        </span>
        <span className="text-[12px] font-semibold text-zinc-200">Filter</span>
        <span className="text-[10px] text-zinc-500">
          {nodeCount} node{nodeCount !== 1 ? "s" : ""}
        </span>
        {filter.searchText && (
          <span className="chip chip-violet !py-0 !text-[9px]">search</span>
        )}
        {!allOn && <span className="chip chip-warn !py-0 !text-[9px]">filtered</span>}
        <span className="text-zinc-500 ml-1 inline-flex">
          <Icon name={open ? "chevronUp" : "chevronDown"} size={11} />
        </span>
      </button>

      {open && (
        <div className="mt-1.5 surface anim-pop p-3 w-60">
          {/* Search */}
          <div className="relative mb-3">
            <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500">
              <Icon name="search" size={11} />
            </span>
            <input
              value={filter.searchText}
              onChange={e => setSearchFilter(e.target.value)}
              placeholder="Search…"
              className="field !pl-7 !py-1.5 !text-[11px]"
            />
            {filter.searchText && (
              <button
                onClick={() => setSearchFilter("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-200"
                aria-label="Clear search"
              >
                <Icon name="close" size={11} />
              </button>
            )}
          </div>

          {/* Header */}
          <div className="flex items-center justify-between mb-2">
            <span className="eyebrow">Entity Types</span>
            <button
              onClick={toggleAll}
              className="text-[10px] text-violet-300 hover:text-violet-200 font-semibold"
            >
              {allOn ? "None" : "All"}
            </button>
          </div>

          {/* Type list */}
          <div className="space-y-0.5">
            {TYPES.map(({ type, label, icon }) => {
              const on = filter.types.has(type);
              return (
                <button
                  key={type}
                  onClick={() => setTypeFilter(type, !on)}
                  className="w-full flex items-center gap-2.5 px-2 py-1.5 rounded-md
                             hover:bg-white/[.04] transition-colors text-left group"
                >
                  <span
                    className={[
                      "flex h-3.5 w-3.5 items-center justify-center rounded border transition-all",
                      on ? "bg-violet-500 border-violet-500" : "border-edge-2 bg-transparent",
                    ].join(" ")}
                  >
                    {on && <Icon name="check" size={9} strokeWidth={3} />}
                  </span>
                  <span className="text-zinc-400 flex items-center" style={{ width: 14 }}>
                    <Icon name={icon} size={13} />
                  </span>
                  <span
                    className={`text-[11.5px] ${
                      on ? "text-zinc-200" : "text-zinc-500"
                    } group-hover:text-white`}
                  >
                    {label}
                  </span>
                </button>
              );
            })}
          </div>

          {(!allOn || filter.searchText) && (
            <button
              onClick={clearFilters}
              className="mt-3 w-full text-center text-[11px] text-zinc-500
                         hover:text-rose-400 transition-colors py-1 border-t border-edge-0"
            >
              Reset filters
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// Memoised: Re-rendered by unrelated canvas interactions.
export default React.memo(FilterPanel);
