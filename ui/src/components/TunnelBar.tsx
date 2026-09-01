/** The public URL, its status, and the compose toggle. */

import { useStore } from "../store";

export function TunnelBar(): React.JSX.Element {
  const tunnel = useStore((s) => s.tunnel);
  const composeOpen = useStore((s) => s.composeOpen);
  const setComposeOpen = useStore((s) => s.setComposeOpen);

  return (
    <header className="tunnel-bar">
      <strong className="tunnel-bar__brand">webhookr</strong>

      <span className={`badge badge--${tunnel.status}`}>{tunnel.status}</span>

      {tunnel.url === null ? (
        <span className="tunnel-bar__url tunnel-bar__url--empty">
          {tunnel.adapter === "none" ? "no tunnel (--no-tunnel)" : "waiting for a public URL…"}
        </span>
      ) : (
        <code className="tunnel-bar__url">{tunnel.url}</code>
      )}

      <button
        type="button"
        className="tunnel-bar__compose"
        aria-pressed={composeOpen}
        onClick={() => setComposeOpen(!composeOpen)}
      >
        {composeOpen ? "close composer" : "compose"}
      </button>
    </header>
  );
}
