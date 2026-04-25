/**
 * Format an ISO date string into a short "M/D H:MM" form suitable for chart labels.
 */
export function formatShortDate(isoStr: string | undefined | null): string {
  if (!isoStr) return '';
  try {
    const d = new Date(isoStr);
    return `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`;
  } catch {
    return '';
  }
}

/**
 * Return a human-readable relative time string (e.g. "3 minutes ago", "2 days ago").
 */
export function relTime(isoStr: string | undefined | null): string {
  if (!isoStr) return '';
  try {
    const d = new Date(isoStr);
    const now = Date.now();
    const diffMs = now - d.getTime();
    if (diffMs < 0) return 'just now';

    const seconds = Math.floor(diffMs / 1000);
    if (seconds < 60) return seconds <= 1 ? 'just now' : `${seconds}s ago`;

    const minutes = Math.floor(seconds / 60);
    if (minutes < 60)
      return minutes === 1 ? '1 minute ago' : `${minutes} minutes ago`;

    const hours = Math.floor(minutes / 60);
    if (hours < 24) return hours === 1 ? '1 hour ago' : `${hours} hours ago`;

    const days = Math.floor(hours / 24);
    if (days < 30) return days === 1 ? '1 day ago' : `${days} days ago`;

    const months = Math.floor(days / 30);
    if (months < 12)
      return months === 1 ? '1 month ago' : `${months} months ago`;

    const years = Math.floor(months / 12);
    return years === 1 ? '1 year ago' : `${years} years ago`;
  } catch {
    return '';
  }
}
