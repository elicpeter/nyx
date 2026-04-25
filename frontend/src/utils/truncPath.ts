/**
 * Truncate a file path to maxLen characters, keeping the tail and prefixing with "...".
 */
export function truncPath(p: string | undefined | null, maxLen = 60): string {
  if (!p) return '';
  if (p.length <= maxLen) return p;
  return '...' + p.slice(-(maxLen - 3));
}
