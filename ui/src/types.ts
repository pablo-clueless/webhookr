/**
 * Mirrors `src/types.rs` field-for-field.
 *
 * Keep the two in sync manually and in the same commit. Drift here is the most
 * likely source of silent UI bugs: the JSON still parses, the field is just
 * `undefined` forever.
 */

export type Verdict = "valid" | "invalid" | "unsigned" | "none";

export type Headers = Record<string, string>;

export interface Endpoint {
  id: string;
  /** The path segment that routes here: `/in/{token}`. */
  token: string;
  name: string;
  forward_url: string | null;
  auto_forward: boolean;
  scheme: string | null;
  secret: string | null;
  resp_status: number;
  resp_body: string;
  resp_headers: Headers;
  resp_delay_ms: number;
  created_at: number;
}

export interface CreateEndpoint {
  name: string;
  scheme?: string | null;
  secret?: string | null;
  forward_url?: string | null;
  auto_forward: boolean;
}

/** Partial update. Omit a field to leave it alone; `null` clears it. */
export type PatchEndpoint = Partial<Omit<Endpoint, "id" | "token" | "created_at">>;

/** List-row shape — carries no body, so the list stays cheap. */
export interface RequestSummary {
  id: string;
  endpoint_id: string;
  method: string;
  path: string;
  query: string;
  remote_addr: string | null;
  verdict: Verdict;
  verdict_detail: string | null;
  /** Body length in bytes. */
  size: number;
  received_at: number;
}

/** The Rust side flattens `summary` into this object, so the shape is flat. */
export interface RequestDetail extends RequestSummary {
  headers: Headers;
  /** Base64 of the raw captured bytes. Decode for display; never assume UTF-8. */
  body_b64: string;
  forwards: Forward[];
}

export interface Forward {
  id: string;
  request_id: string;
  target: string;
  status: number | null;
  duration_ms: number | null;
  resp_body_b64: string | null;
  error: string | null;
  sent_at: number;
}

export interface ReplayRequest {
  /** Overrides the endpoint's `forward_url` for this replay. */
  target?: string;
  /**
   * Send the captured bytes and headers verbatim instead of re-signing.
   * Use it to check that a handler rejects stale deliveries.
   */
  preserve_signature?: boolean;
}

export interface ComposeRequest {
  target: string;
  method: string;
  headers: Headers;
  /** Base64 of the body to send. */
  body_b64: string;
  scheme?: string | null;
  secret?: string | null;
}

export interface SignRequest {
  body_b64: string;
  scheme: string;
  secret: string;
  /** Unix seconds. Defaults to now for schemes that embed a timestamp. */
  timestamp?: number;
}

export interface SignResponse {
  headers: Headers;
}

export type TunnelStatus = "up" | "down" | "starting";

export interface TunnelInfo {
  url: string | null;
  adapter: string;
  status: TunnelStatus;
}

/** Scheme names the server's registry accepts. */
export const SCHEMES = ["stripe", "github", "svix", "hmac_generic"] as const;
export type Scheme = (typeof SCHEMES)[number];

// ------------------------------------------------------------- SSE payloads

/** `event: request` */
export interface RequestFrame {
  request: RequestSummary;
}

/** `event: forward` */
export interface ForwardFrame {
  request_id: string;
  forward: Forward;
}

/** `event: tunnel` */
export interface TunnelFrame {
  url: string | null;
  status: TunnelStatus;
}
