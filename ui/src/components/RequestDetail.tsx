/**
 * Headers, body, and delivery attempts for the selected request.
 *
 * The body is decoded here, in the browser, from the base64 field — that is the
 * only place a captured payload is ever parsed. The server keeps it as opaque
 * bytes end to end so the signature stays verifiable (invariant 1).
 */

import { bodyAsText } from "../api";
import { useStore } from "../store";

export function RequestDetail(): React.JSX.Element {
  const detail = useStore((s) => s.detail);
  const selectedRequestId = useStore((s) => s.selectedRequestId);

  if (selectedRequestId === null) {
    return <p className="empty">Select a request.</p>;
  }
  if (detail === null) {
    return <p className="empty">Loading…</p>;
  }

  const text = bodyAsText(detail.body_b64);

  return (
    <>
      <h2 className="pane__title">
        {detail.method} /{detail.path}
        <span className={`badge badge--${detail.verdict}`}>{detail.verdict}</span>
      </h2>

      {detail.verdict_detail !== null && <p className="detail__verdict">{detail.verdict_detail}</p>}

      <section>
        <h3>Headers</h3>
        <dl className="headers">
          {Object.entries(detail.headers).map(([name, value]) => (
            <div key={name}>
              <dt>{name}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section>
        <h3>Body ({detail.size} bytes)</h3>
        {text === null ? (
          <p className="empty">Binary body — {detail.size} bytes, not valid UTF-8.</p>
        ) : (
          <pre className="body">{prettyIfJson(text)}</pre>
        )}
      </section>

      <section>
        <h3>Forwards</h3>
        {detail.forwards.length === 0 ? (
          <p className="empty">Not forwarded yet.</p>
        ) : (
          <ul className="forwards">
            {detail.forwards.map((forward) => (
              <li key={forward.id}>
                <code>{forward.target}</code>
                <span>{forward.error ?? forward.status ?? "—"}</span>
                {forward.duration_ms !== null && <span>{forward.duration_ms}ms</span>}
              </li>
            ))}
          </ul>
        )}
        {/* TODO(phase 3): replay button, target override, and the
            preserve_signature toggle for testing stale-delivery rejection. */}
      </section>
    </>
  );
}

/**
 * Formats a JSON body for reading only. This is display-side and deliberately
 * one-way — the reformatted text is never sent anywhere, because re-serializing
 * reorders keys and would change the digest.
 */
function prettyIfJson(text: string): string {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}
