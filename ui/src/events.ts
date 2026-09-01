/**
 * The server→client half of the transport.
 *
 * `EventSource` over SSE, not a WebSocket: the traffic only flows one way, it
 * survives proxies, and the browser reconnects on its own. Frames land straight
 * in the zustand store — there is no component in the callback path.
 */

import { useStore } from "./store";
import type { ForwardFrame, RequestFrame, TunnelFrame } from "./types";

const ENDPOINT = "/api/events";

/**
 * Opens the stream. Returns a teardown function.
 *
 * Call once at mount. The named events match the `event:` lines the server
 * emits in `src/server/events.rs`.
 */
export function connectEvents(): () => void {
  const source = new EventSource(ENDPOINT);
  const store = useStore.getState();

  const on = <T>(name: string, handle: (payload: T) => void): void => {
    source.addEventListener(name, (event) => {
      try {
        handle(JSON.parse((event as MessageEvent<string>).data) as T);
      } catch (e) {
        console.error(`[webhookr] malformed ${name} frame`, e);
      }
    });
  };

  on<RequestFrame>("request", ({ request }) => store.pushRequest(request));
  on<ForwardFrame>("forward", ({ request_id, forward }) =>
    store.attachForward(request_id, forward),
  );
  on<TunnelFrame>("tunnel", ({ url, status }) => store.setTunnel({ url, status }));

  // EventSource retries on its own, so an error here is informational. It fires
  // on every reconnect attempt; do not tear the stream down in response.
  source.addEventListener("error", () => {
    if (source.readyState === EventSource.CLOSED) {
      console.warn("[webhookr] event stream closed");
    }
  });

  return () => source.close();
}
