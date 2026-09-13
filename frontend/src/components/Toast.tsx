// src/components/Toast.tsx
import React, { createContext, useCallback, useContext, useState } from "react";
import { Icon, type IconName } from "./Icons";

type Kind = "info" | "success" | "warn" | "error";
interface Toast {
  id: number;
  kind: Kind;
  title: string;
  message?: string;
}

interface Ctx { push: (kind: Kind, title: string, message?: string) => void; }
const ToastCtx = createContext<Ctx>({ push: () => {} });
export const useToast = () => useContext(ToastCtx);

let _id = 0;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);

  const push = useCallback((kind: Kind, title: string, message?: string) => {
    const id = ++_id;
    setItems(v => [...v, { id, kind, title, message }]);
    setTimeout(() => setItems(v => v.filter(t => t.id !== id)), 4200);
  }, []);

  const dismiss = (id: number) => setItems(v => v.filter(t => t.id !== id));

  return (
    <ToastCtx.Provider value={{ push }}>
      {children}
      <div className="fixed bottom-5 right-5 z-[110] space-y-2.5 pointer-events-none">
        {items.map(t => (
          <ToastCard key={t.id} t={t} onClose={() => dismiss(t.id)} />
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

const TONE: Record<Kind, { icon: IconName; ring: string; text: string }> = {
  info:    { icon: "activity", ring: "border-sky-500/30 bg-sky-500/10",         text: "text-sky-300"     },
  success: { icon: "check",    ring: "border-emerald-500/30 bg-emerald-500/10", text: "text-emerald-300" },
  warn:    { icon: "alert",    ring: "border-amber-500/30 bg-amber-500/10",     text: "text-amber-300"   },
  error:   { icon: "close",    ring: "border-rose-500/30 bg-rose-500/10",       text: "text-rose-300"    },
};

function ToastCard({ t, onClose }: { t: Toast; onClose: () => void }) {
  const tone = TONE[t.kind];
  return (
    <div
      className={`pointer-events-auto min-w-[280px] max-w-sm
                  rounded-xl border ${tone.ring}
                  backdrop-blur-xl bg-ink-850/90 px-4 py-3
                  shadow-float anim-slide-r flex items-start gap-3`}
    >
      <span className={`mt-0.5 shrink-0 ${tone.text}`}>
        <Icon name={tone.icon} size={14} strokeWidth={2.25} />
      </span>
      <div className="flex-1 min-w-0">
        <p className="text-[13px] font-semibold text-white leading-snug">{t.title}</p>
        {t.message && (
          <p className="text-[11px] text-zinc-400 mt-0.5 leading-snug">{t.message}</p>
        )}
      </div>
      <button
        onClick={onClose}
        className="text-zinc-500 hover:text-zinc-200 shrink-0 mt-0.5"
        aria-label="Dismiss"
      >
        <Icon name="close" size={12} />
      </button>
    </div>
  );
}