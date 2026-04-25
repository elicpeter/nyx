import { useCallback, useEffect, useRef, useState } from 'react';

type Status = 'idle' | 'working' | 'copied' | 'failed';

interface CopyMarkdownButtonProps {
  getMarkdown: () => string | Promise<string>;
  label?: string;
  className?: string;
  title?: string;
  stopPropagation?: boolean;
  iconOnly?: boolean;
}

const COPIED_MS = 1500;
const FAILED_MS = 2000;

const ICON_SIZE = 14;

function CopyIcon() {
  return (
    <svg
      width={ICON_SIZE}
      height={ICON_SIZE}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <rect x="5" y="5" width="9" height="9" rx="1.5" />
      <path d="M11 5V3.5A1.5 1.5 0 0 0 9.5 2h-6A1.5 1.5 0 0 0 2 3.5v6A1.5 1.5 0 0 0 3.5 11H5" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg
      width={ICON_SIZE}
      height={ICON_SIZE}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M3 8.5l3 3 7-7" />
    </svg>
  );
}

function FailIcon() {
  return (
    <svg
      width={ICON_SIZE}
      height={ICON_SIZE}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M4 4l8 8M12 4l-8 8" />
    </svg>
  );
}

export function CopyMarkdownButton({
  getMarkdown,
  label = 'Copy',
  className,
  title,
  stopPropagation,
  iconOnly,
}: CopyMarkdownButtonProps) {
  const [status, setStatus] = useState<Status>('idle');
  const timeoutRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (timeoutRef.current != null) {
        window.clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  const scheduleReset = useCallback((ms: number) => {
    if (timeoutRef.current != null) window.clearTimeout(timeoutRef.current);
    timeoutRef.current = window.setTimeout(() => {
      setStatus('idle');
      timeoutRef.current = null;
    }, ms);
  }, []);

  const handleClick = useCallback(
    async (e: React.MouseEvent<HTMLButtonElement>) => {
      if (stopPropagation) e.stopPropagation();
      if (status === 'working') return;
      if (
        typeof navigator === 'undefined' ||
        !navigator.clipboard ||
        typeof navigator.clipboard.writeText !== 'function'
      ) {
        setStatus('failed');
        scheduleReset(FAILED_MS);
        return;
      }
      setStatus('working');
      try {
        const text = await getMarkdown();
        await navigator.clipboard.writeText(text);
        setStatus('copied');
        scheduleReset(COPIED_MS);
      } catch (err) {
        console.error('CopyMarkdownButton: failed to copy', err);
        setStatus('failed');
        scheduleReset(FAILED_MS);
      }
    },
    [getMarkdown, scheduleReset, status, stopPropagation],
  );

  const displayLabel =
    status === 'working'
      ? 'Copying…'
      : status === 'copied'
        ? 'Copied!'
        : status === 'failed'
          ? 'Failed'
          : label;

  const classes = [
    'btn',
    'btn-sm',
    'copy-btn',
    iconOnly ? 'copy-btn--icon' : '',
    status === 'copied' ? 'copy-btn--copied' : '',
    status === 'failed' ? 'copy-btn--failed' : '',
    className || '',
  ]
    .filter(Boolean)
    .join(' ');

  const icon =
    status === 'copied' ? (
      <CheckIcon />
    ) : status === 'failed' ? (
      <FailIcon />
    ) : (
      <CopyIcon />
    );

  return (
    <button
      type="button"
      className={classes}
      title={title ?? (iconOnly ? displayLabel : undefined)}
      aria-label={iconOnly ? displayLabel : undefined}
      disabled={status === 'working'}
      onClick={handleClick}
    >
      {iconOnly ? icon : displayLabel}
    </button>
  );
}
