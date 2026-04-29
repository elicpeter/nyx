interface ShortcutsHelpProps {
  open: boolean;
  onClose: () => void;
}

interface Row {
  keys: string[];
  description: string;
}

const ROWS: { section: string; rows: Row[] }[] = [
  {
    section: 'Global',
    rows: [
      { keys: ['⌘', 'K'], description: 'Open command palette' },
      { keys: ['/'], description: 'Focus search (on findings page)' },
      { keys: ['?'], description: 'Show this help' },
      { keys: ['Esc'], description: 'Close modal / palette' },
    ],
  },
  {
    section: 'Findings list',
    rows: [
      { keys: ['j'], description: 'Next finding' },
      { keys: ['k'], description: 'Previous finding' },
      { keys: ['Enter'], description: 'Open highlighted finding' },
    ],
  },
  {
    section: 'Navigation',
    rows: [
      { keys: ['g', 'o'], description: 'Go to Overview' },
      { keys: ['g', 'f'], description: 'Go to Findings' },
      { keys: ['g', 's'], description: 'Go to Scans' },
      { keys: ['g', 'r'], description: 'Go to Rules' },
      { keys: ['g', 't'], description: 'Go to Triage' },
    ],
  },
];

export function ShortcutsHelp({ open, onClose }: ShortcutsHelpProps) {
  if (!open) return null;
  return (
    <div
      className="palette-overlay"
      role="dialog"
      aria-label="Keyboard shortcuts"
    >
      <div className="palette-backdrop" onClick={onClose} />
      <div className="shortcuts-modal">
        <div className="shortcuts-header">
          <h2>Keyboard shortcuts</h2>
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            onClick={onClose}
            aria-label="Close shortcuts help"
          >
            Close
          </button>
        </div>
        <div className="shortcuts-body">
          {ROWS.map((section) => (
            <section key={section.section}>
              <h3>{section.section}</h3>
              <dl>
                {section.rows.map((row) => (
                  <div key={row.description} className="shortcut-row">
                    <dt>
                      {row.keys.map((k, i) => (
                        <span key={i}>
                          {i > 0 && <span className="shortcut-sep">then</span>}
                          <kbd>{k}</kbd>
                        </span>
                      ))}
                    </dt>
                    <dd>{row.description}</dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
