// ts-safe-014: direct-return path sanitiser.
import * as fs from 'fs';

function sanitizePath(s: string): string {
  if (s.includes('..') || s.startsWith('/') || s.startsWith('\\')) {
    return '';
  }
  return s;
}

export default function (req: { query: { path: string } }) {
  const raw = req.query.path;
  const safe = sanitizePath(raw);
  return fs.readFileSync(safe);
}
