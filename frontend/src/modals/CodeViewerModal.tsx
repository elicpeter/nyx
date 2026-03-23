import { useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Modal } from '../components/ui/Modal';
import { apiGet } from '../api/client';
import { highlightSyntax, escapeHtml } from '../utils/syntaxHighlight';
import type { FindingView, FileResponse } from '../api/types';

interface CodeViewerModalProps {
  open: boolean;
  onClose: () => void;
  finding: FindingView | null;
}

export function CodeViewerModal({ open, onClose, finding }: CodeViewerModalProps) {
  const bodyRef = useRef<HTMLDivElement>(null);

  const { data: fileData, isLoading, error } = useQuery({
    queryKey: ['files', finding?.path],
    queryFn: ({ signal }) =>
      apiGet<FileResponse>(`/files?path=${encodeURIComponent(finding?.path || '')}`, signal),
    enabled: open && !!finding?.path,
    staleTime: 5 * 60_000, // cache file content for 5 minutes
  });

  // Scroll to finding line after content renders
  useEffect(() => {
    if (!fileData || !finding || !bodyRef.current) return;
    const timer = requestAnimationFrame(() => {
      const target = bodyRef.current?.querySelector(`[data-line="${finding.line}"]`);
      if (target) target.scrollIntoView({ block: 'center', behavior: 'smooth' });
    });
    return () => cancelAnimationFrame(timer);
  }, [fileData, finding]);

  if (!open || !finding) return null;

  const sourceLine = finding.evidence?.source?.line;
  const sinkLine = finding.evidence?.sink?.line;
  const findingLine = finding.line;
  const lang = (finding.language || '').toLowerCase();

  return (
    <Modal open={open} onClose={onClose} className="code-modal-overlay">
      <div className="code-modal">
        <div className="code-modal-header">
          <span className="code-modal-title">{finding.path}</span>
          <button className="btn btn-sm code-modal-close" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="code-modal-body" ref={bodyRef}>
          {isLoading && (
            <div className="loading" style={{ padding: 40, textAlign: 'center' }}>
              Loading file...
            </div>
          )}
          {error && (
            <div className="error-state" style={{ padding: 40 }}>
              <p>Could not load file: {error instanceof Error ? error.message : 'Unknown error'}</p>
            </div>
          )}
          {fileData && (
            <div className="code-viewer-body">
              {fileData.lines.map((l) => {
                let cls = 'code-line';
                if (l.number === sourceLine) cls += ' highlight-source';
                else if (l.number === sinkLine) cls += ' highlight-sink';
                else if (l.number === findingLine) cls += ' highlight-finding';
                return (
                  <div key={l.number} className={cls} data-line={l.number}>
                    <span className="line-number">{l.number}</span>
                    <span
                      className="line-content"
                      dangerouslySetInnerHTML={{
                        __html: highlightSyntax(escapeHtml(l.content), lang),
                      }}
                    />
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}
