/**
 * REST client. The client→server half of the transport; the server→client half
 * is SSE, in `events.ts`.
 */

import type {
  ComposeRequest,
  CreateEndpoint,
  Endpoint,
  Forward,
  PatchEndpoint,
  RequestDetail,
  RequestSummary,
  SignRequest,
  SignResponse,
  TunnelInfo,
} from "./types";

/** Shape of the server's error body: `{ "error": "..." }`. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init?.body === undefined ? {} : { "content-type": "application/json" }),
      ...init?.headers,
    },
  });

  if (!response.ok) {
    // The server always answers JSON, but a proxy in the middle might not.
    const detail = await response
      .json()
      .then((body: { error?: string }) => body.error)
      .catch(() => undefined);
    throw new ApiError(response.status, detail ?? `${response.status} ${response.statusText}`);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const json = (body: unknown): string => JSON.stringify(body);

export const api = {
  listEndpoints: () => request<Endpoint[]>("/api/endpoints"),

  createEndpoint: (input: CreateEndpoint) =>
    request<Endpoint>("/api/endpoints", { method: "POST", body: json(input) }),

  patchEndpoint: (id: string, patch: PatchEndpoint) =>
    request<Endpoint>(`/api/endpoints/${id}`, { method: "PATCH", body: json(patch) }),

  deleteEndpoint: (id: string) => request<void>(`/api/endpoints/${id}`, { method: "DELETE" }),

  listRequests: (params: { endpoint_id?: string; limit?: number; before?: number } = {}) => {
    const query = new URLSearchParams();
    if (params.endpoint_id) query.set("endpoint_id", params.endpoint_id);
    if (params.limit !== undefined) query.set("limit", String(params.limit));
    if (params.before !== undefined) query.set("before", String(params.before));
    const suffix = query.size > 0 ? `?${query}` : "";
    return request<RequestSummary[]>(`/api/requests${suffix}`);
  },

  getRequest: (id: string) => request<RequestDetail>(`/api/requests/${id}`),

  deleteRequest: (id: string) => request<void>(`/api/requests/${id}`, { method: "DELETE" }),

  replay: (id: string, body: { target?: string; preserve_signature?: boolean } = {}) =>
    request<Forward>(`/api/requests/${id}/replay`, { method: "POST", body: json(body) }),

  compose: (body: ComposeRequest) =>
    request<Forward>("/api/compose", { method: "POST", body: json(body) }),

  sign: (body: SignRequest) =>
    request<SignResponse>("/api/sign", { method: "POST", body: json(body) }),

  tunnel: () => request<TunnelInfo>("/api/tunnel"),
};

// ------------------------------------------------------------ body encoding

/**
 * Bodies cross the API base64-encoded so a non-UTF-8 payload survives the trip.
 * These two are the only place the UI converts between the two forms.
 */

export function decodeBody(bodyB64: string): Uint8Array {
  const binary = atob(bodyB64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function encodeBody(bytes: Uint8Array | string): string {
  const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  let binary = "";
  for (const byte of data) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Best-effort text view of a captured body. Returns null if it is not UTF-8. */
export function bodyAsText(bodyB64: string): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(decodeBody(bodyB64));
  } catch {
    return null;
  }
}
