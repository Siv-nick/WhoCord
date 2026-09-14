// src/hooks/useSSE.ts
// ─────────────────────────────────────────────────────────────────────────────
// Typed EventSource hook. Parses every SSE message as a JSON envelope
// { type: string, payload: object } and calls the appropriate handler.
//
// Reconnect behaviour
// -------------------
// The browser's native EventSource auto-reconnects on transient network
// drops, with its own backoff. The previous version of this hook defeated
// that by calling close() in onerror, permanently killing the stream on
// any momentary hiccup even though the job kept running server-side.
//
// This version:
//   • never calls close() from onerror
//   • lets the browser retry
//   • surfaces onReconnect so the caller can show "reconnecting…"
//   • only closes on a terminal event, unmount, or explicit closeStream()
//   • tracks consecutive failed retries and calls onGiveUp after a cap

import { useEffect, useRef } from "react";
import type { EventType, SSEEvent } from "../types/investigation";

interface UseSSEOptions {
  /** Called for every successfully parsed event. */
  onEvent: (event: SSEEvent) => void;
  /** Called when the EventSource fires an error (network drop, etc.). */
  onError?: (err: Event) => void;
  /** Called when the stream ends (EventSource is closed by server or by us). */
  onClose?: () => void;
  /**
   * Called when the browser has auto-reconnected after a transient drop.
   * Fires on the `open` event that follows one or more `error` events.
   */
  onReconnect?: (attempt: number) => void;
  /** Automatically close the EventSource when one of these event types arrives. */
  closeOn?: EventType[];
  /**
   * Maximum consecutive reconnect attempts before the hook calls onGiveUp.
   * Defaults to 10 (~browser-managed backoff typically retries within ~30s).
   */
  maxRetries?: number;
  /** Called when maxRetries is exhausted. */
  onGiveUp?: () => void;
}

/**
 * Open an SSE stream to `url` and dispatch structured events.
 *
 * The hook returns a `close` ref so callers can imperatively close the stream
 * (e.g. when a Stop button is pressed).
 *
 * The EventSource is automatically cleaned up when the component unmounts or
 * when `url` changes.
 *
 * @example
 * ```tsx
 * const { closeStream } = useSSE(sseUrl, {
 *   onEvent: (e) => dispatch({ type: "SSE_EVENT", event: e }),
 *   onReconnect: () => toast.push("info", "Reconnecting…"),
 *   closeOn: ["stream_end", "error"],
 * });
 * ```
 */
export function useSSE(
  url: string | null,
  options: UseSSEOptions,
): { closeStream: () => void } {
  const esRef        = useRef<EventSource | null>(null);
  const closeRef     = useRef<() => void>(() => {});
  const optsRef      = useRef(options);
  optsRef.current = options;   // keep latest handlers without re-running effect

  // Track consecutive errors since the last successful open. A new
  // connection resets the counter — see es.onopen.
  const retryCountRef = useRef(0);

  useEffect(() => {
    if (!url) return;

    let disposed = false;

    const es = new EventSource(url);
    esRef.current = es;

    const close = () => {
      if (disposed) return;
      disposed = true;
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
      }
      optsRef.current.onClose?.();
    };
    closeRef.current = close;

    es.onopen = () => {
      // Successful (re)connection — reset the retry counter.
      const attempts = retryCountRef.current;
      retryCountRef.current = 0;
      if (attempts > 0) {
        optsRef.current.onReconnect?.(attempts);
      }
    };

    es.onmessage = (msgEvent: MessageEvent) => {
      let parsed: SSEEvent;
      try {
        parsed = JSON.parse(msgEvent.data) as SSEEvent;
      } catch {
        // Treat unparseable messages as raw log lines.
        parsed = { type: "log", payload: { line: msgEvent.data } };
      }

      optsRef.current.onEvent(parsed);

      if (optsRef.current.closeOn?.includes(parsed.type)) {
        close();
      }
    };

    es.onerror = (err: Event) => {
      // Do NOT close. The browser will retry automatically.
      retryCountRef.current += 1;

      optsRef.current.onError?.(err);

      const cap = optsRef.current.maxRetries ?? 10;
      if (retryCountRef.current >= cap) {
        // Give up after sustained failure — the caller can decide what
        // to show. We close the raw EventSource so it stops spinning,
        // but leave it to the caller to transition UI state.
        optsRef.current.onGiveUp?.();
        close();
      }
    };

    return () => {
      close();
    };
    // We deliberately depend only on `url`. Handlers are read from
    // optsRef on every event, so callers can update them without
    // tearing down the stream.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url]);

  return { closeStream: () => closeRef.current() };
}