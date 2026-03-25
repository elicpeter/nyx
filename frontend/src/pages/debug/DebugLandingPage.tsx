export function DebugLandingPage() {
  return (
    <div className="debug-landing">
      <h2>Global Debug Views</h2>
      <p className="text-secondary">
        Use Debug for project-wide and engine-level inspection. File-local
        representations now live in Explorer.
      </p>
      <div className="debug-landing-grid">
        <div className="card">
          <h3>CFG</h3>
          <p>
            File-local CFG inspection now belongs in Explorer alongside code and
            other per-file representations.
          </p>
        </div>
        <div className="card">
          <h3>SSA</h3>
          <p>
            File-local SSA inspection now belongs in Explorer under the selected
            file.
          </p>
        </div>
        <div className="card">
          <h3>Call Graph</h3>
          <p>Explore the project-wide call graph with SCC highlighting.</p>
        </div>
        <div className="card">
          <h3>Summaries</h3>
          <p>Inspect global summary-store data across the project.</p>
        </div>
        <div className="card">
          <h3>Explorer</h3>
          <p>
            Open a file, then inspect CFG, SSA, taint, summaries, abstract
            interpretation, and symbolic execution in one place.
          </p>
        </div>
      </div>
    </div>
  );
}
