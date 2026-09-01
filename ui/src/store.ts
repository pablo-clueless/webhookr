/**
 * The application store.
 *
 * This is zustand rather than `useState` for one specific reason: SSE frames
 * arrive from outside React's tree, and the request list has to accept a push
 * from an `EventSource` callback that has no component to live in. A store with
 * a stable module-level handle makes that a one-liner instead of a context
 * dance.
 */

import { create } from "zustand";

import { api } from "./api";
import type { Endpoint, Forward, RequestDetail, RequestSummary, TunnelInfo } from "./types";

/** How many rows the list holds before old ones are dropped. */
const MAX_ROWS = 500;

interface State {
  endpoints: Endpoint[];
  /** `null` means "all endpoints". */
  activeEndpointId: string | null;

  requests: RequestSummary[];
  selectedRequestId: string | null;
  /** Full detail for the selected row, fetched lazily. */
  detail: RequestDetail | null;

  tunnel: TunnelInfo;
  composeOpen: boolean;
  error: string | null;
}

interface Actions {
  loadEndpoints: () => Promise<void>;
  selectEndpoint: (id: string | null) => Promise<void>;

  loadRequests: () => Promise<void>;
  selectRequest: (id: string | null) => Promise<void>;

  /** Called from the SSE handler — prepends a row arriving from outside React. */
  pushRequest: (request: RequestSummary) => void;
  /** Called from the SSE handler when a forward completes. */
  attachForward: (requestId: string, forward: Forward) => void;
  setTunnel: (tunnel: Partial<TunnelInfo>) => void;

  setComposeOpen: (open: boolean) => void;
  setError: (error: string | null) => void;
}

export const useStore = create<State & Actions>((set, get) => ({
  endpoints: [],
  activeEndpointId: null,
  requests: [],
  selectedRequestId: null,
  detail: null,
  tunnel: { url: null, adapter: "none", status: "down" },
  composeOpen: false,
  error: null,

  loadEndpoints: async () => {
    try {
      const endpoints = await api.listEndpoints();
      set((s) => ({
        endpoints,
        activeEndpointId: s.activeEndpointId ?? endpoints[0]?.id ?? null,
      }));
    } catch (e) {
      set({ error: describe(e) });
    }
  },

  selectEndpoint: async (id) => {
    set({ activeEndpointId: id, selectedRequestId: null, detail: null });
    await get().loadRequests();
  },

  loadRequests: async () => {
    const { activeEndpointId } = get();
    try {
      const requests = await api.listRequests(
        activeEndpointId === null ? {} : { endpoint_id: activeEndpointId },
      );
      set({ requests });
    } catch (e) {
      set({ error: describe(e) });
    }
  },

  selectRequest: async (id) => {
    set({ selectedRequestId: id, detail: null });
    if (id === null) return;
    try {
      const detail = await api.getRequest(id);
      // Guard against a slow fetch resolving after the selection moved on.
      if (get().selectedRequestId === id) set({ detail });
    } catch (e) {
      set({ error: describe(e) });
    }
  },

  pushRequest: (request) =>
    set((s) => {
      // A frame for an endpoint we are not looking at is still worth ignoring
      // quietly rather than mixing into a filtered list.
      if (s.activeEndpointId !== null && request.endpoint_id !== s.activeEndpointId) {
        return s;
      }
      return { requests: [request, ...s.requests].slice(0, MAX_ROWS) };
    }),

  attachForward: (requestId, forward) =>
    set((s) =>
      s.detail?.id === requestId
        ? { detail: { ...s.detail, forwards: [...s.detail.forwards, forward] } }
        : s,
    ),

  setTunnel: (tunnel) => set((s) => ({ tunnel: { ...s.tunnel, ...tunnel } })),

  setComposeOpen: (composeOpen) => set({ composeOpen }),
  setError: (error) => set({ error }),
}));

/** Selector for the endpoint the list is currently filtered to. */
export function useActiveEndpoint(): Endpoint | null {
  return useStore((s) => s.endpoints.find((e) => e.id === s.activeEndpointId) ?? null);
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
