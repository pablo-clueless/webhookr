/**
 * Fires a hand-written payload at any target, optionally signed.
 *
 * Freeform JSON by design — v1 ships no provider event catalogue.
 */

import { useState } from "react";

import { api, encodeBody } from "../api";
import { useStore } from "../store";
import { SCHEMES } from "../types";

const DEFAULT_BODY = `{\n  "id": "evt_test",\n  "type": "ping"\n}`;

export function ComposePanel(): React.JSX.Element {
  const setError = useStore((s) => s.setError);

  const [target, setTarget] = useState("http://localhost:3000/webhooks");
  const [method, setMethod] = useState("POST");
  const [body, setBody] = useState(DEFAULT_BODY);
  const [scheme, setScheme] = useState<string>("");
  const [secret, setSecret] = useState("");
  const [sending, setSending] = useState(false);

  const send = async (): Promise<void> => {
    setSending(true);
    try {
      await api.compose({
        target,
        method,
        headers: { "content-type": "application/json" },
        body_b64: encodeBody(body),
        scheme: scheme === "" ? null : scheme,
        secret: secret === "" ? null : secret,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSending(false);
    }
  };

  return (
    <>
      <h2 className="pane__title">Compose</h2>

      <label>
        Target
        <input value={target} onChange={(e) => setTarget(e.target.value)} />
      </label>

      <label>
        Method
        <select value={method} onChange={(e) => setMethod(e.target.value)}>
          {["POST", "PUT", "PATCH", "GET", "DELETE"].map((m) => (
            <option key={m}>{m}</option>
          ))}
        </select>
      </label>

      <label>
        Scheme
        <select value={scheme} onChange={(e) => setScheme(e.target.value)}>
          <option value="">unsigned</option>
          {SCHEMES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </label>

      {scheme !== "" && (
        <label>
          Secret
          <input
            type="password"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="whsec_…"
          />
        </label>
      )}

      <label>
        Body
        <textarea rows={12} value={body} onChange={(e) => setBody(e.target.value)} />
      </label>

      <button type="button" disabled={sending} onClick={() => void send()}>
        {sending ? "sending…" : "send"}
      </button>

      {/* TODO(phase 5): show the generated signature headers via POST /api/sign
          before sending, and render the resulting Forward inline. */}
    </>
  );
}
