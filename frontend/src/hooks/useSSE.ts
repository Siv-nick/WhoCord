// src/hooks/useSSE.ts
// ─────────────────────────────────────────────────────────────────────────────
// Typed EventSource hook.  Parses every SSE message as a JSON envelope
// { type: string, payload: object } and calls the appropriate handler.

import { useEffect, useRef } from "react";
import type { EventType, SSEEvent } from "../types/investigation";

interface UseSSEOptions {
  /** Called for every successfully parsed event. */
  onEvent: (event: SSEEvent) => void;
  /** Called when the EventSource fires an error (network drop, etc.). */
  onError?: (err: Event) => void;
  /** Called when the stream ends (EventSource is closed by server or by us). */
  onClose?: () => void;
  /** Automatically close the EventSource when one of these event types arrives. */
  closeOn?: EventType[];
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
 *   closeOn: ["stream_end", "error"],
 * });
 * ```
 */
export function useSSE(
  url: string | null,
  options: UseSSEOptions,
): { closeStream: () => void } {
  const esRef    = useRef<EventSource | null>(null);
  const closeRef = useRef<() => void>(() => {});
  const optsRef  = useRef(options);
  optsRef.current = options;   // keep latest handlers without re-running effect

  useEffect(() => {
    if (!url) return;

    const es = new EventSource(url);
    esRef.current = es;

    const close = () => {
      if (esRef.current) {
        esRef.current.close();
        esRef.current = null;
        optsRef.current.onClose?.();
      }
    };
    closeRef.current = close;

    es.onmessage = (msgEvent: MessageEvent) => {
      let parsed: SSEEvent;
      try {
        parsed = JSON.parse(msgEvent.data) as SSEEvent;
      } catch {
        // Treat unparseable messages as raw log lines
        parsed = { type: "log", payload: { line: msgEvent.data } };
      }

      optsRef.current.onEvent(parsed);

      if (optsRef.current.closeOn?.includes(parsed.type)) {
        close();
      }
    };

    es.onerror = (err: Event) => {
      optsRef.current.onError?.(err);
      close();
    };

    return () => {
      close();
    };
  }, [url]);

  return { closeStream: () => closeRef.current() };
}
