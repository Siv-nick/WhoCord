// src/hooks/useJobCost.ts
import { useEffect, useState } from "react";
import { fetchJobCost } from "../utils/api";
import type { CostSummary } from "../types/investigation";

const POLL_INTERVAL_MS = 3_000;

/**
 * Polls /api/investigations/<jobId>/cost while a job exists, and keeps
 * the last snapshot when the job finishes so the pill does not blank
 * out the moment the run ends.
 *
 * Returns null when there is no job, when the endpoint is unavailable,
 * or when the backend has no cost accumulator for the job.
 */
export function useJobCost(
  jobId: string | null,
  running: boolean,
): CostSummary | null {
  const [cost, setCost] = useState<CostSummary | null>(null);

  useEffect(() => {
    if (!jobId) {
      setCost(null);
      return;
    }

    let cancelled = false;

    const refresh = async () => {
      const c = await fetchJobCost(jobId);
      if (!cancelled && c) setCost(c);
    };

    // Immediate fetch so the pill appears without waiting a full tick.
    refresh();

    // Only poll while the job is actually running. `running` was in the
    // dependency list but nothing branched on it, so the interval was
    // recreated on completion and kept firing every 3s for as long as
    // the operator stayed on the canvas — indefinite background
    // network and render traffic for a job that finished hours ago.
    // A finished job's cost is final, so the single fetch above is
    // enough.
    if (!running) {
      return () => { cancelled = true; };
    }

    const iv = window.setInterval(refresh, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(iv);
    };
  }, [jobId, running]);

  return cost;
}