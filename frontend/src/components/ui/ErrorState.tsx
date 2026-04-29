import { ApiError } from '../../api/client';
import { RefreshIcon } from '../icons/Icons';

interface ErrorStateProps {
  title?: string;
  /** Either a plain message string or any thrown value (Error, ApiError, unknown). */
  message?: string;
  error?: unknown;
  onRetry?: () => void;
  retryLabel?: string;
}

interface FriendlyError {
  title: string;
  message: string;
  hint?: string;
}

/** Translate a thrown value into a title + message + hint we can render. */
function friendly(error: unknown, fallbackTitle: string): FriendlyError {
  if (error instanceof ApiError) {
    if (error.isNetwork()) {
      return {
        title: 'Network error',
        message: error.message || 'Could not reach the Nyx server.',
      };
    }
    if (error.status === 404) {
      return { title: 'Not found', message: error.message };
    }
    if (error.status === 403) {
      return { title: 'Forbidden', message: error.message };
    }
    if (error.status === 409) {
      return { title: 'Conflict', message: error.message };
    }
    if (error.status >= 500) {
      return {
        title: 'Server error',
        message: error.message || 'The Nyx server returned an error.',
        hint: 'Server logs may have more detail.',
      };
    }
    return { title: fallbackTitle, message: error.message };
  }
  if (error instanceof Error) {
    return { title: fallbackTitle, message: error.message };
  }
  if (typeof error === 'string') {
    return { title: fallbackTitle, message: error };
  }
  return { title: fallbackTitle, message: 'An unknown error occurred.' };
}

export function ErrorState({
  title,
  message,
  error,
  onRetry,
  retryLabel = 'Try again',
}: ErrorStateProps) {
  const fallbackTitle = title ?? 'Error';
  const resolved = error
    ? friendly(error, fallbackTitle)
    : { title: fallbackTitle, message: message ?? 'An error occurred.' };

  return (
    <div className="error-state" role="alert">
      <h3>{resolved.title}</h3>
      <p>{resolved.message}</p>
    </div>
  );
}
