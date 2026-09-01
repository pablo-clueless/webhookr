/** Endpoints, and the filter driving the request list. */

import { useStore } from "../store";

export function EndpointList(): React.JSX.Element {
  const endpoints = useStore((s) => s.endpoints);
  const activeEndpointId = useStore((s) => s.activeEndpointId);
  const selectEndpoint = useStore((s) => s.selectEndpoint);

  return (
    <>
      <h2 className="pane__title">Endpoints</h2>

      <ul className="endpoints">
        <li>
          <button
            type="button"
            className={activeEndpointId === null ? "is-active" : ""}
            onClick={() => void selectEndpoint(null)}
          >
            All endpoints
          </button>
        </li>

        {endpoints.map((endpoint) => (
          <li key={endpoint.id}>
            <button
              type="button"
              className={endpoint.id === activeEndpointId ? "is-active" : ""}
              onClick={() => void selectEndpoint(endpoint.id)}
            >
              <span className="endpoints__name">{endpoint.name}</span>
              <code className="endpoints__token">/in/{endpoint.token}</code>
              {endpoint.scheme !== null && (
                <span className="endpoints__scheme">{endpoint.scheme}</span>
              )}
            </button>
          </li>
        ))}
      </ul>

      {/* TODO(phase 5): create / edit / delete, forward_url, auto_forward,
          scheme + secret, and the configurable response. */}
    </>
  );
}
