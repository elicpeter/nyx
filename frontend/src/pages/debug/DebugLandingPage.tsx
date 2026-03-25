export function DebugLandingPage() {
  return (
    <div className="debug-landing">
      <h2>Debug Views</h2>
      <p className="text-secondary">
        Select a tab above and enter a file path and function name to inspect
        engine internals.
      </p>
      <div className="debug-landing-grid">
        <div className="card">
          <h3>CFG</h3>
          <p>
            Visualize control flow graphs for individual functions with
            block-level detail and edge types.
          </p>
        </div>
        <div className="card">
          <h3>SSA</h3>
          <p>
            Inspect SSA intermediate representation including phi nodes, value
            numbering, and instructions.
          </p>
        </div>
        <div className="card">
          <h3>Call Graph</h3>
          <p>Explore the inter-procedural call graph with SCC highlighting.</p>
        </div>
        <div className="card">
          <h3>Taint</h3>
          <p>
            Step through taint propagation with per-block state and sink events.
          </p>
        </div>
        <div className="card">
          <h3>Summaries</h3>
          <p>
            Browse interprocedural function summaries — source/sanitizer/sink
            caps, param flows.
          </p>
        </div>
        <div className="card">
          <h3>Abstract Interp</h3>
          <p>
            View interval and string abstract domain facts per program point.
          </p>
        </div>
        <div className="card">
          <h3>Symex</h3>
          <p>Inspect symbolic expression trees and path constraints.</p>
        </div>
      </div>
    </div>
  );
}
