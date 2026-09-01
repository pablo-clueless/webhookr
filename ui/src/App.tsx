/**
 * Application shell.
 *
 * TODO(phase 5): port the layout and palette from the `hookr-ui.jsx` prototype
 * into these components. The prototype is a visual reference only — its state
 * is `useState`; the real one is the zustand store in `store.ts`.
 */

import { useEffect } from "react";

import { connectEvents } from "./events";
import { useStore } from "./store";
import { ComposePanel } from "./components/ComposePanel";
import { EndpointList } from "./components/EndpointList";
import { RequestDetail } from "./components/RequestDetail";
import { RequestList } from "./components/RequestList";
import { TunnelBar } from "./components/TunnelBar";

export function App(): React.JSX.Element {
  const composeOpen = useStore((s) => s.composeOpen);
  const error = useStore((s) => s.error);
  const setError = useStore((s) => s.setError);

  useEffect(() => {
    const store = useStore.getState();
    void store.loadEndpoints().then(() => store.loadRequests());

    // One subscription for the life of the app. Frames reach the store
    // directly, so nothing here needs to re-run when state changes.
    return connectEvents();
  }, []);

  return (
    <div className="app">
      <TunnelBar />

      {error !== null && (
        <div className="banner banner--error" role="alert">
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)}>
            dismiss
          </button>
        </div>
      )}

      <main className="panes">
        <aside className="pane pane--endpoints">
          <EndpointList />
        </aside>
        <section className="pane pane--requests">
          <RequestList />
        </section>
        <section className="pane pane--detail">
          {composeOpen ? <ComposePanel /> : <RequestDetail />}
        </section>
      </main>
    </div>
  );
}
