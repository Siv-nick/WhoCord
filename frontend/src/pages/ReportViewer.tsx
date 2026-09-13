// src/pages/ReportViewer.tsx
import React, { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { investigationReportUrl } from "../utils/api";
import { Icon } from "../components/Icons";

type LoadState = "loading" | "ready" | "error";

export default function ReportViewer() {
  const { jobId }           = useParams<{ jobId?: string }>();
  const navigate            = useNavigate();
  const iframeRef           = useRef<HTMLIFrameElement>(null);
  const [loadState, setLS]  = useState<LoadState>("loading");
  const [errorMsg, setEM]   = useState("");

  const reportUrl = jobId ? investigationReportUrl(jobId) : "/report";

  useEffect(() => {
    setLS("loading");
    setEM("");
  }, [reportUrl]);

  const handleIframeLoad = () => {
    try {
      const doc = iframeRef.current?.contentDocument;
      const title = doc?.title ?? "";
      const body  = doc?.body?.innerText ?? "";
      if (title === "404" || body.includes("not found") || body.includes("No report")) {
        setLS("error");
        setEM("Report not found or not yet generated.");
        return;
      }
    } catch {
      // cross-origin iframe — assume it loaded fine
    }
    setLS("ready");
  };

  const handleIframeError = () => {
    setLS("error");
    setEM("Failed to load report.");
  };

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-edge-0
                      bg-ink-900/60 backdrop-blur-xl shrink-0">
        <button onClick={() => navigate(-1)} className="btn btn-ghost !p-2" aria-label="Back">
          <Icon name="arrowLeft" size={14} />
        </button>

        <span className="text-sm font-semibold text-white flex-1 truncate">
          {jobId ? `Report · ${jobId.slice(0, 8)}…` : "Latest report"}
        </span>

        {loadState === "loading" && (
          <span className="text-[11px] text-violet-400 animate-pulse">Loading…</span>
        )}

        {loadState === "ready" && (
          <a
            href={reportUrl}
            target="_blank"
            rel="noreferrer"
            className="btn"
          >
            <Icon name="external" size={11} /> Open in tab
          </a>
        )}

        <button
          onClick={() => {
            setLS("loading");
            if (iframeRef.current) iframeRef.current.src = reportUrl;
          }}
          className="btn"
        >
          <Icon name="refresh" size={11} /> Reload
        </button>
      </div>

      {/* Content */}
      {loadState === "error" ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-4 text-center p-8">
          <div className="h-14 w-14 rounded-full border border-edge-1 bg-ink-850
                          flex items-center justify-center text-zinc-600">
            <Icon name="alert" size={20} />
          </div>
          <p className="text-sm text-zinc-400">{errorMsg}</p>
          <button onClick={() => navigate("/")} className="btn btn-primary">
            <Icon name="sparkle" size={12} /> New investigation
          </button>
        </div>
      ) : (
        <div className="flex-1 relative">
          {loadState === "loading" && (
            <div className="absolute inset-0 flex items-center justify-center
                            bg-ink-950 z-10">
              <div className="flex flex-col items-center gap-3">
                <div className="w-8 h-8 rounded-full border-2 border-violet-500
                                border-t-transparent animate-spin" />
                <p className="text-sm text-zinc-500">Loading report…</p>
              </div>
            </div>
          )}
          <iframe
            ref={iframeRef}
            src={reportUrl}
            title="Investigation Report"
            className="w-full h-full border-0 bg-white"
            onLoad={handleIframeLoad}
            onError={handleIframeError}
          />
        </div>
      )}
    </div>
  );
}