/**
 * Captured requests, newest first.
 *
 * Rows arrive two ways: the initial fetch, and SSE frames pushed into the store
 * from outside React's tree.
 */

import { useStore } from "../store";
import type { Verdict } from "../types";

const VERDICT_LABEL: Record<Verdict, string> = {
  valid: "signature ok",
  invalid: "signature mismatch",
  unsigned: "no signature sent",
  none: "no scheme configured",
};

export function RequestList(): React.JSX.Element {
  const requests = useStore((s) => s.requests);
  const selectedRequestId = useStore((s) => s.selectedRequestId);
  const selectRequest = useStore((s) => s.selectRequest);

  return (
    <>
      <h2 className="pane__title">Requests</h2>

      {requests.length === 0 ? (
        <p className="empty">
          Nothing captured yet. Deliver something to <code>/in/&#123;token&#125;</code>.
        </p>
      ) : (
        <ul className="requests">
          {requests.map((request) => (
            <li key={request.id}>
              <button
                type="button"
                className={request.id === selectedRequestId ? "is-active" : ""}
                onClick={() => void selectRequest(request.id)}
              >
                <span className="requests__method">{request.method}</span>
                <span className="requests__path">/{request.path}</span>
                <span
                  className={`badge badge--${request.verdict}`}
                  title={request.verdict_detail ?? VERDICT_LABEL[request.verdict]}
                >
                  {request.verdict}
                </span>
                <time
                  className="requests__time"
                  dateTime={new Date(request.received_at).toISOString()}
                >
                  {new Date(request.received_at).toLocaleTimeString()}
                </time>
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
