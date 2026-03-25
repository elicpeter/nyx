import { Modal } from '../components/ui/Modal';
import { CodeViewer } from '../components/data-display/CodeViewer';
import type { FindingView } from '../api/types';

interface CodeViewerModalProps {
  open: boolean;
  onClose: () => void;
  finding: FindingView | null;
}

export function CodeViewerModal({
  open,
  onClose,
  finding,
}: CodeViewerModalProps) {
  if (!open || !finding) return null;

  return (
    <Modal open={open} onClose={onClose} className="code-modal-overlay">
      <div className="code-modal">
        <div className="code-modal-header">
          <span className="code-modal-title">{finding.path}</span>
          <button className="btn btn-sm code-modal-close" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="code-modal-body">
          <CodeViewer
            filePath={finding.path}
            language={finding.language || ''}
            highlights={{
              sourceLine: finding.evidence?.source?.line,
              sinkLine: finding.evidence?.sink?.line,
              findingLine: finding.line,
            }}
            highlightLine={finding.line}
          />
        </div>
      </div>
    </Modal>
  );
}
