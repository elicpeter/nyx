import { useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../../api/client';
import { highlightSyntax, escapeHtml } from '../../utils/syntaxHighlight';
import type { FileResponse, ExplorerFinding } from '../../api/types';

interface LineHighlights {
  sourceLine?: number;
  sinkLine?: number;
  findingLine?: number;
}

interface CodeViewerProps {
  filePath: string;
  findings?: ExplorerFinding[];
  highlights?: LineHighlights;
  highlightLine?: number;
  flowLines?: Set<number>;
  language?: string;
  className?: string;
  initialScrollTop?: number;
  onScrollPositionChange?: (scrollTop: number) => void;
}

export function CodeViewer({
  filePath,
  findings,
  highlights,
  highlightLine,
  flowLines,
  language,
  className,
  initialScrollTop,
  onScrollPositionChange,
}: CodeViewerProps) {
  const bodyRef = useRef<HTMLDivElement>(null);

  const {
    data: fileData,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['files', filePath],
    queryFn: ({ signal }) =>
      apiGet<FileResponse>(
        `/files?path=${encodeURIComponent(filePath)}`,
        signal,
      ),
    enabled: !!filePath,
    staleTime: 5 * 60_000,
  });

  const scrollTarget = highlightLine ?? highlights?.findingLine;

  useEffect(() => {
    if (!fileData || !scrollTarget || !bodyRef.current) return;
    const timer = requestAnimationFrame(() => {
      const target = bodyRef.current?.querySelector(
        `[data-line="${scrollTarget}"]`,
      );
      if (target)
        target.scrollIntoView({ block: 'center', behavior: 'smooth' });
    });
    return () => cancelAnimationFrame(timer);
  }, [fileData, scrollTarget]);

  useEffect(() => {
    if (
      !fileData ||
      scrollTarget ||
      initialScrollTop == null ||
      !bodyRef.current
    ) {
      return;
    }

    const timer = requestAnimationFrame(() => {
      if (bodyRef.current) {
        bodyRef.current.scrollTop = initialScrollTop;
      }
    });

    return () => cancelAnimationFrame(timer);
  }, [fileData, initialScrollTop, scrollTarget]);

  // Build a set of finding lines for gutter markers
  const findingsByLine = new Map<number, ExplorerFinding>();
  if (findings) {
    for (const f of findings) {
      // Keep the highest severity per line
      const existing = findingsByLine.get(f.line);
      if (
        !existing ||
        severityRank(f.severity) > severityRank(existing.severity)
      ) {
        findingsByLine.set(f.line, f);
      }
    }
  }

  const lang = (language || '').toLowerCase();

  if (isLoading) {
    return (
      <div className={className} style={{ padding: 40, textAlign: 'center' }}>
        Loading file...
      </div>
    );
  }

  if (error) {
    return (
      <div className={className}>
        <div className="error-state" style={{ padding: 40 }}>
          <p>
            Could not load file:{' '}
            {error instanceof Error ? error.message : 'Unknown error'}
          </p>
        </div>
      </div>
    );
  }

  if (!fileData) return null;

  return (
    <div
      className={`code-viewer-body ${className || ''}`}
      ref={bodyRef}
      onScroll={(event) =>
        onScrollPositionChange?.(event.currentTarget.scrollTop)
      }
    >
      {fileData.lines.map((l) => {
        let cls = 'code-line';
        if (highlights) {
          if (l.number === highlights.sourceLine) cls += ' highlight-source';
          else if (l.number === highlights.sinkLine) cls += ' highlight-sink';
          else if (l.number === highlights.findingLine)
            cls += ' highlight-finding';
          else if (flowLines?.has(l.number)) cls += ' highlight-flow';
        } else if (highlightLine && l.number === highlightLine) {
          cls += ' highlight-finding';
        }

        const gutterFinding = findingsByLine.get(l.number);

        return (
          <div key={l.number} className={cls} data-line={l.number}>
            <span className="line-gutter">
              {gutterFinding ? (
                <span
                  className={`gutter-marker sev-${gutterFinding.severity.toLowerCase()}`}
                  title={`${gutterFinding.rule_id}: ${gutterFinding.message || gutterFinding.category}`}
                />
              ) : (
                <span className="gutter-marker-spacer" />
              )}
            </span>
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
  );
}

function severityRank(s: string): number {
  switch (s.toUpperCase()) {
    case 'HIGH':
      return 3;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 1;
    default:
      return 0;
  }
}
