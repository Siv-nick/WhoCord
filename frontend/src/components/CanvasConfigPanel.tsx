// src/components/CanvasConfigPanel.tsx
import React, { useEffect, useRef, useState } from "react";
import {
  apiFetch,
  fetchConfig,
  fetchLLMModels,
  saveLLMConfig,
  saveOutputFormat,
  savePivotConfig,
  saveEnrichmentConfig,
  setToken,
  testEnrichmentProvider,
  toggleDebug,
  toggleTool,
  upgradeToolsUrl,
  type LLMModel,
  type LLMConfig,
} from "../utils/api";
import type {
  AppConfig,
  EnrichmentTestResult,
  LLMProvider,
  OutputFormat,
  PivotConfig,
  ToolConfig,
} from "../types/investigation";
import { Icon } from "./Icons";

const DEFAULT_PIVOT: PivotConfig = {
  enabled:         false,
  pivot_email:     true,
  pivot_username:  true,
  max_depth:       3,
  max_seeds:       5,
  require_confirm: false,
};

const DEFAULT_LLM: LLMConfig = {
  provider:           "groq",
  model:              "llama3-8b-8192",
  temperature:        0.25,
  max_tokens:         4096,
  system_prompt:      "",
  intel_budget:       60000,
  intel_include_raw:  true,
  intel_exclude_meta: true,
};

const PROVIDER_DESCRIPTIONS: Record<LLMProvider, string> = {
  groq:       "Ultra-fast inference. Free tier is per-minute token limited — pick a small model on big graphs.",
  openrouter: "Routes to hundreds of models. Free tier is request-count limited (50/day) — no per-minute token cap.",
  ollama:     "Local inference via Ollama. No investigation data leaves your machine — the full intel dump stays on disk.",
};

const PROVIDER_DEFAULT_MODEL: Record<LLMProvider, string> = {
  groq:       "llama3-8b-8192",
  openrouter: "deepseek/deepseek-chat-v3.1:free",
  ollama:     "llama3.2:latest",
};

const OUTPUT_FORMAT_LABELS: Record<OutputFormat, string> = {
  html:     "HTML report (recommended)",
  markdown: "Markdown only",
  json:     "JSON only",
};

interface Props {
  isOpen:  boolean;
  onClose: () => void;
}

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

  const [llm,          setLLM]          = useState<LLMConfig>(DEFAULT_LLM);
  const [llmModels,    setLLMModels]    = useState<LLMModel[]>([]);
  const [llmModelsSrc, setLLMModelsSrc] = useState<"live" | "fallback" | null>(null);
  const [llmModelsMsg, setLLMModelsMsg] = useState<string>("");
  const [llmLoading,   setLLMLoading]   = useState(false);
  const [llmSaved,     setLLMSaved]     = useState(false);

  const [outputFormat, setOutputFormat] = useState<OutputFormat>("html");
  const [formatSaved,  setFormatSaved]  = useState(false);

  const [enrMaxIdents, setEnrMaxIdents] = useState<number>(25);
  const [enrPhone,     setEnrPhone]     = useState<boolean>(false);
  const [enrSaved,     setEnrSaved]     = useState(false);
  const [testState,    setTestState]    = useState<Record<
    "apollo" | "lusha",
    { busy: boolean; result: EnrichmentTestResult | null }
  >>({
    apollo: { busy: false, result: null },
    lusha:  { busy: false, result: null },
  });

  const load = async () => {
    setLoading(true);
    try {
      const data = await fetchConfig();
      setCfg(data);
      setPivot(data.pivot ?? DEFAULT_PIVOT);
      if (data.llm) setLLM({ ...DEFAULT_LLM, ...data.llm });
      if (data.output_format) setOutputFormat(data.output_format);
      if (data.enrichment) {
        setEnrMaxIdents(data.enrichment.max_identifiers ?? 25);
        setEnrPhone(data.enrichment.phone_reveal ?? false);
      }
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  };

  const loadModels = async () => {
    setLLMLoading(true);
    try {
      const res = await fetchLLMModels();
      setLLMModels(res.models);
      setLLMModelsSrc(res.source);
      setLLMModelsMsg(res.reason ?? "");
    } catch (err) {
      setLLMModels([]);
      setLLMModelsSrc(null);
      setLLMModelsMsg(String(err));
    } finally {
      setLLMLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      load().then(() => loadModels());
    }
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

  const handleSaveLLM = async () => {
    try {
      await saveLLMConfig(llm);
      setLLMSaved(true);
      setTimeout(() => setLLMSaved(false), 2500);
    } catch (err) {
      console.warn("saveLLMConfig failed:", err);
    }
  };

  const handleSaveFormat = async () => {
    try {
      await saveOutputFormat(outputFormat);
      setFormatSaved(true);
      setTimeout(() => setFormatSaved(false), 2500);
    } catch (err) {
      console.warn("saveOutputFormat failed:", err);
    }
  };

  const handleSwitchProvider = async (next: LLMProvider) => {
    if (next === llm.provider) return;

    // Always use the target provider's default model on switch. The old
    // heuristic ("contains a slash → openrouter") can't distinguish
    // Ollama's family:tag names from Groq's names, and it silently
    // carried over an unusable model id.
    const nextLlm: LLMConfig = {
      ...llm,
      provider: next,
      model:    PROVIDER_DEFAULT_MODEL[next],
    };
    setLLM(nextLlm);
    try {
      await saveLLMConfig(nextLlm);
    } catch (err) {
      console.warn("provider switch save failed:", err);
    }
    await loadModels();
  };

  const handleSaveEnrichment = async () => {
    try {
      await saveEnrichmentConfig({
        max_identifiers: enrMaxIdents,
        phone_reveal:    enrPhone,
      });
      setEnrSaved(true);
      setTimeout(() => setEnrSaved(false), 2500);
    } catch (err) {
      console.warn("saveEnrichmentConfig failed:", err);
    }
  };

  const handleTestEnrichment = async (provider: "apollo" | "lusha") => {
    setTestState(prev => ({
      ...prev,
      [provider]: { busy: true, result: null },
    }));
    const res = await testEnrichmentProvider(provider);
    setTestState(prev => ({
      ...prev,
      [provider]: { busy: false, result: res },
    }));
  };

  const handleUpgrade = async () => {
    setLog([]);
    setUpgrading(true);
    try {
      const res    = await apiFetch(upgradeToolsUrl(), { method: "POST" });
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
    DISCORD_TOKEN:      "Discord Token",
    GITHUB_TOKEN:       "GitHub Token",
    GROQ_API_KEY:       "Groq API Key",
    OPENROUTER_API_KEY: "OpenRouter API Key",
    HIBP_API_KEY:       "HIBP API Key (v3)",
    INSTAGRAM_SESSION:  "Instagram Session",
    APOLLO_API_KEY:     "Apollo.io API Key (paid credits)",
    LUSHA_API_KEY:      "Lusha API Key (paid credits)",
    CORD_CAT_API_KEY:   "CordCat API Key",
    TINEYE_API_KEY:     "TinEye API Key (paid API)",
  };

  const llmModelOptions = (() => {
    if (llmModels.length === 0) return [{ id: llm.model, owned_by: "custom" }];
    if (llmModels.some(m => m.id === llm.model)) return llmModels;
    return [{ id: llm.model, owned_by: "custom" }, ...llmModels];
  })();

  const providerKeyStored = (() => {
    if (!cfg) return false;
    if (llm.provider === "ollama") return true;   // local server, no key
    return llm.provider === "groq"
      ? cfg.tokens.GROQ_API_KEY
      : cfg.tokens.OPENROUTER_API_KEY;
  })();

  const discordTokenMissing = cfg && !cfg.tokens.DISCORD_TOKEN;

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm anim-in"
        onClick={onClose}
      />

      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
        <div
          className="surface anim-pop flex flex-col pointer-events-auto w-full"
          style={{ maxWidth: "min(720px, 96vw)", maxHeight: "86vh" }}
          onClick={e => e.stopPropagation()}
        >
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

              {discordTokenMissing && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/[.06]
                                px-3 py-2.5 text-[12px] text-amber-200 leading-snug">
                  <div className="flex items-start gap-2">
                    <span className="shrink-0 mt-0.5"><Icon name="alert" size={13} /></span>
                    <div>
                      <p className="font-semibold">Discord token is not set.</p>
                      <p className="text-amber-200/80 mt-0.5">
                        Discord mode and guild message search will not run.
                        All other modules work without it. Add a token below
                        if you intend to investigate Discord users.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              <section>
                <h3 className="text-[13px] font-bold text-white mb-3 flex items-center gap-2">
                  <Icon name="key" size={14} className="text-violet-300" />
                  API Tokens
                </h3>
                <p className="text-[11px] text-zinc-500 -mt-1 mb-3 leading-snug">
                  Tokens are stored in the OS keyring. The badge shows
                  whether a value is present — it does not validate that the
                  value is currently accepted by the provider.
                </p>
                <div className="space-y-3">
                  {cfg && Object.entries(TOKEN_LABELS).map(([key, label]) => {
                    const isStored = Boolean(cfg.tokens[key as keyof typeof cfg.tokens]);
                    return (
                      <div key={key}>
                        <label className="flex items-center justify-between text-[11px] text-zinc-500 mb-1">
                          <span>{label}</span>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              isStored
                                ? "bg-emerald-500/15 text-emerald-300"
                                : "bg-white/[.03] text-zinc-500"
                            }`}
                          >
                            {isStored ? "stored" : "empty"}
                          </span>
                        </label>
                        <input
                          type="password"
                          placeholder={isStored ? "Replace stored value…" : `Enter ${label}…`}
                          value={tokenInputs[key] ?? ""}
                          onChange={e =>
                            setTI(p => ({ ...p, [key]: e.target.value }))
                          }
                          className="field !py-1.5 !text-sm"
                        />
                      </div>
                    );
                  })}
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

              <section>
                <h3 className="text-[13px] font-bold text-white mb-1 flex items-center gap-2">
                  <Icon name="layout" size={14} className="text-violet-300" />
                  Report Output
                </h3>
                <p className="text-[11px] text-zinc-500 mb-3 leading-snug">
                  Format written at the end of every investigation. The HTML
                  report is self-contained and opens offline; markdown and
                  JSON are useful when feeding the result into another tool.
                </p>
                <div className="space-y-1.5">
                  {(["html", "markdown", "json"] as OutputFormat[]).map(fmt => {
                    const active = outputFormat === fmt;
                    return (
                      <button
                        key={fmt}
                        type="button"
                        onClick={() => setOutputFormat(fmt)}
                        className={[
                          "w-full text-left rounded-lg border px-3 py-2 transition-all",
                          active
                            ? "border-violet-500/60 bg-violet-500/15 text-violet-100"
                            : "border-edge-1 bg-ink-800/50 text-zinc-300 hover:border-edge-2",
                        ].join(" ")}
                      >
                        <p className="text-[12px] font-bold">
                          {fmt.toUpperCase()}
                        </p>
                        <p className="text-[10px] text-zinc-500 leading-snug mt-0.5">
                          {OUTPUT_FORMAT_LABELS[fmt]}
                        </p>
                      </button>
                    );
                  })}
                </div>
                <div className="flex items-center gap-3 mt-3">
                  <button onClick={handleSaveFormat} className="btn btn-primary">
                    <Icon name="check" size={12} /> Save format
                  </button>
                  {formatSaved && (
                    <span className="text-[12px] text-emerald-400">Saved</span>
                  )}
                </div>
              </section>

              <section>
                <h3 className="text-[13px] font-bold text-white mb-1 flex items-center gap-2">
                  <Icon name="sparkle" size={14} className="text-violet-300" />
                  AI Model &amp; Prompt
                  {llmModelsSrc === "live" && (
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded
                                     bg-emerald-500/15 text-emerald-300">
                      LIVE
                    </span>
                  )}
                  {llmModelsSrc === "fallback" && (
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded
                                     bg-amber-500/15 text-amber-300"
                          title={llmModelsMsg}>
                      FALLBACK
                    </span>
                  )}
                </h3>
                <p className="text-[11px] text-zinc-500 mb-4">
                  Applies to the AI persona summary, structured report,
                  intelligence narrative, and the canvas chat.
                </p>

                <div className="mb-4">
                  <label className="block text-[11px] text-zinc-500 mb-1.5">
                    Provider
                  </label>
                  <div className="grid grid-cols-3 gap-2">
                    {(["groq", "openrouter", "ollama"] as LLMProvider[]).map(p => {
                      const active = llm.provider === p;
                      const sub =
                        p === "groq"       ? "Fast, TPM-limited"
                        : p === "openrouter" ? "Broad, request-limited"
                        : "Local, offline";
                      const label =
                        p === "groq"       ? "Groq"
                        : p === "openrouter" ? "OpenRouter"
                        : "Ollama";
                      return (
                        <button
                          key={p}
                          type="button"
                          onClick={() => handleSwitchProvider(p)}
                          className={[
                            "rounded-lg border px-3 py-2 text-left transition-all",
                            active
                              ? "border-violet-500/60 bg-violet-500/15 text-violet-100"
                              : "border-edge-1 bg-ink-800/50 text-zinc-300 hover:border-edge-2",
                          ].join(" ")}
                        >
                          <p className="text-[12px] font-bold">{label}</p>
                          <p className="text-[10px] text-zinc-500 leading-snug mt-0.5">
                            {sub}
                          </p>
                        </button>
                      );
                    })}
                  </div>
                  <p className="mt-1.5 text-[10px] text-zinc-500 leading-snug">
                    {PROVIDER_DESCRIPTIONS[llm.provider]}
                  </p>
                  {!providerKeyStored && llm.provider !== "ollama" && (
                    <p className="mt-1.5 text-[10px] text-amber-400/80 leading-snug">
                      {llm.provider === "groq"
                        ? "No Groq API key stored. Add one in the API Tokens section above."
                        : "No OpenRouter API key stored. Add one in the API Tokens section above."}
                    </p>
                  )}
                </div>

                <div className="mb-4">
                  <label className="flex items-center justify-between text-[11px] text-zinc-500 mb-1">
                    <span>Model</span>
                    <button
                      type="button"
                      onClick={loadModels}
                      disabled={llmLoading}
                      className="text-[10px] text-violet-300 hover:text-violet-200
                                 disabled:opacity-40"
                    >
                      {llmLoading ? "Refreshing…" : "↻ Refresh list"}
                    </button>
                  </label>
                  <select
                    value={llm.model}
                    onChange={e => setLLM(p => ({ ...p, model: e.target.value }))}
                    className="field !py-1.5 !text-sm font-mono"
                    disabled={llmLoading}
                  >
                    {llmModelOptions.map(m => (
                      <option key={m.id} value={m.id}>
                        {m.id}{m.owned_by === "custom" ? "  (custom)" : ""}
                        {(m as LLMModel).free ? "  · free" : ""}
                      </option>
                    ))}
                  </select>
                  {llmModelsSrc === "fallback" && llmModelsMsg && (
                    <p className="mt-1 text-[10px] text-amber-400/80 leading-snug">
                      {llmModelsMsg}
                    </p>
                  )}
                </div>

                <div className="mb-4">
                  <label className="flex justify-between text-[11px] text-zinc-500 mb-1">
                    <span>Temperature</span>
                    <span className="font-bold text-white tabular-nums">
                      {llm.temperature.toFixed(2)}
                    </span>
                  </label>
                  <input
                    type="range"
                    min={0}
                    max={2}
                    step={0.05}
                    value={llm.temperature}
                    onChange={e =>
                      setLLM(p => ({ ...p, temperature: Number(e.target.value) }))
                    }
                    className="w-full accent-violet-500"
                  />
                  <div className="flex justify-between text-[10px] text-zinc-600 mt-0.5">
                    <span>0.0 · deterministic</span>
                    <span>2.0 · chaotic</span>
                  </div>
                </div>

                <div className="mb-4">
                  <label className="flex justify-between text-[11px] text-zinc-500 mb-1">
                    <span>Max output tokens</span>
                    <span className="font-bold text-white tabular-nums">
                      {llm.max_tokens}
                    </span>
                  </label>
                  <input
                    type="range"
                    min={256}
                    max={16384}
                    step={256}
                    value={llm.max_tokens}
                    onChange={e =>
                      setLLM(p => ({ ...p, max_tokens: Number(e.target.value) }))
                    }
                    className="w-full accent-violet-500"
                  />
                </div>

                <div className="mb-4">
                  <label className="flex items-center justify-between text-[11px] text-zinc-500 mb-1">
                    <span>System prompt</span>
                    <span className="text-[10px] text-zinc-600">
                      {llm.system_prompt.length} chars
                    </span>
                  </label>
                  <textarea
                    value={llm.system_prompt}
                    onChange={e =>
                      setLLM(p => ({ ...p, system_prompt: e.target.value }))
                    }
                    placeholder="Leave blank to use each tool's built-in default prompt."
                    rows={5}
                    className="field !text-[12px] font-mono resize-y leading-relaxed !py-2"
                  />
                  <p className="mt-1 text-[10px] text-zinc-600 leading-snug">
                    Applied to every AI call. The untrusted-data contract is
                    always appended regardless of what you enter here.
                  </p>
                </div>

                <div className="mb-4 pt-3 border-t border-edge-0">
                  <label className="flex justify-between text-[11px] text-zinc-500 mb-1">
                    <span>Intel dump budget</span>
                    <span className="font-bold text-white tabular-nums">
                      {llm.intel_budget.toLocaleString()} chars
                    </span>
                  </label>
                  <input
                    type="range"
                    min={5000}
                    max={200000}
                    step={5000}
                    value={llm.intel_budget}
                    onChange={e =>
                      setLLM(p => ({
                        ...p,
                        intel_budget: Number(e.target.value),
                      }))
                    }
                    className="w-full accent-violet-500"
                  />
                  <p className="mt-1 text-[10px] text-zinc-600 leading-snug">
                    Split between the canvas map and the intel dump sent with
                    each AI call. Larger = more context = slower.
                  </p>
                </div>

                <div className="mb-4 space-y-2">
                  <Toggle
                    on={llm.intel_include_raw}
                    onToggle={() =>
                      setLLM(p => ({
                        ...p,
                        intel_include_raw: !p.intel_include_raw,
                      }))
                    }
                    label="Include raw API responses"
                    sublabel="Adds api_data and raw_tool_output sections"
                  />
                  <Toggle
                    on={llm.intel_exclude_meta}
                    onToggle={() =>
                      setLLM(p => ({
                        ...p,
                        intel_exclude_meta: !p.intel_exclude_meta,
                      }))
                    }
                    label="Exclude prior AI output"
                    sublabel="Skip intelligence_report and persona_summary to avoid feedback loops"
                  />
                </div>

                <div className="flex items-center gap-3">
                  <button onClick={handleSaveLLM} className="btn btn-primary">
                    <Icon name="check" size={12} /> Save AI settings
                  </button>
                  {llmSaved && (
                    <span className="text-[12px] text-emerald-400">Saved</span>
                  )}
                </div>
              </section>

              {cfg && (
                <section>
                  <h3 className="text-[13px] font-bold text-white mb-1 flex items-center gap-2">
                    <Icon name="globe" size={14} className="text-violet-300" />
                    Contact Enrichment
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded
                                     bg-amber-500/15 text-amber-300">
                      PAID CREDITS
                    </span>
                  </h3>
                  <p className="text-[11px] text-zinc-500 mb-4 leading-snug">
                    Apollo and Lusha both charge per successful match. Every
                    identifier passes through the trust filter before it is
                    submitted; rejects are logged in the report with a reason.
                    Both providers are opt-in and default to off.
                  </p>

                  <div className="space-y-3 mb-4">
                    {(["apollo", "lusha"] as const).map(provider => {
                      const enabled = cfg.enrichment.enabled[provider];
                      const stored  = cfg.enrichment.keys_stored[provider];
                      const toggleKey = provider === "apollo" ? "ENABLE_APOLLO" : "ENABLE_LUSHA";
                      const tool = cfg.tools.find(t => t.key === toggleKey);
                      const tstate = testState[provider];

                      return (
                        <div key={provider} className="rounded-lg border border-edge-1
                                                       bg-ink-800/50 px-3 py-3 space-y-2">
                          <Toggle
                            on={Boolean(tool?.enabled ?? enabled)}
                            onToggle={async () => {
                              if (tool) {
                                await toggleTool(tool.key, !tool.enabled);
                                await load();
                              }
                            }}
                            label={provider === "apollo" ? "Apollo.io" : "Lusha"}
                            sublabel={
                              stored
                                ? "API key stored — ready to enrich"
                                : "No API key stored — add one in API Tokens above"
                            }
                          />
                          <div className="flex items-center gap-2 pl-12">
                            <button
                              type="button"
                              onClick={() => handleTestEnrichment(provider)}
                              disabled={!stored || tstate.busy}
                              className="btn !text-[10px] !px-2 !py-1
                                         disabled:!opacity-40"
                            >
                              <Icon name="refresh" size={11} />
                              {tstate.busy ? "Testing…" : "Test connection"}
                            </button>
                            {tstate.result && (
                              <span
                                className={`text-[10px] ${
                                  tstate.result.ok ? "text-emerald-400" : "text-rose-400"
                                }`}
                              >
                                {tstate.result.ok
                                  ? tstate.result.balance !== null &&
                                    tstate.result.balance !== undefined
                                    ? `✓ OK · balance ${
                                        typeof tstate.result.balance === "number"
                                          ? tstate.result.balance
                                          : JSON.stringify(tstate.result.balance)
                                      }`
                                    : "✓ OK"
                                  : `✗ ${tstate.result.error ?? "failed"}`}
                              </span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  <div className="mb-4">
                    <label className="flex justify-between text-[11px] text-zinc-500 mb-1">
                      <span>Max identifiers submitted per provider</span>
                      <span className="font-bold text-white tabular-nums">
                        {enrMaxIdents}
                      </span>
                    </label>
                    <input
                      type="range"
                      min={1}
                      max={100}
                      step={1}
                      value={enrMaxIdents}
                      onChange={e => setEnrMaxIdents(Number(e.target.value))}
                      className="w-full accent-violet-500"
                    />
                    <p className="mt-1 text-[10px] text-zinc-600 leading-snug">
                      Hard cap on how many identifiers can be submitted to
                      each provider per run. Rejected identifiers do not
                      count against this cap.
                    </p>
                  </div>

                  <Toggle
                    on={enrPhone}
                    onToggle={() => setEnrPhone(v => !v)}
                    label="Reveal phone numbers (Lusha)"
                    sublabel="Costs 5 extra credits per contact. Neither provider accepts phones as input — phones are only revealed for already-matched people."
                  />

                  <div className="flex items-center gap-3 mt-4">
                    <button onClick={handleSaveEnrichment} className="btn btn-primary">
                      <Icon name="check" size={12} /> Save enrichment settings
                    </button>
                    {enrSaved && (
                      <span className="text-[12px] text-emerald-400">Saved</span>
                    )}
                  </div>
                </section>
              )}

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
                          <span>Batch size per pivot wave</span>
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
                        <p className="mt-1 text-[10px] text-zinc-600 leading-snug">
                          Seeds beyond this number are investigated in a
                          subsequent wave at the same depth — none are dropped.
                        </p>
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
                        sublabel="Show all seeds at a depth, then wait for your approval (45s default; timeouts skip)"
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

              {cfg && (
                <section>
                  <h3 className="text-[13px] font-bold text-white mb-3 flex items-center gap-2">
                    <Icon name="server" size={14} className="text-violet-300" />
                    Tools
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {cfg.tools.map(tool => (
                      <button
                        key={tool.key}
                        type="button"
                        onClick={() => handleToggleTool(tool)}
                        className="flex items-center justify-between rounded-lg
                                   border border-edge-1 bg-ink-800/50 px-3 py-2 cursor-pointer
                                   hover:border-edge-2 transition-colors text-left"
                      >
                        <span className="text-[11px] text-zinc-300">{tool.desc}</span>
                        <div
                          className={`relative w-8 h-4 rounded-full transition-colors shrink-0 ml-2 ${
                            tool.enabled ? "bg-violet-600" : "bg-edge-2"
                          }`}
                          aria-hidden="true"
                        >
                          <div
                            className={`absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white
                                        transition-transform ${
                                          tool.enabled ? "translate-x-4" : ""
                                        }`}
                          />
                        </div>
                      </button>
                    ))}
                  </div>
                </section>
              )}

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