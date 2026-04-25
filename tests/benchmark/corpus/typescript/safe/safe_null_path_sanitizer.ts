// ts-safe-015: nullable-returning sanitiser (`string | null`).
import * as fs from 'fs';

function sanitizePath(s: string): string | null {
  if (s.includes('..') || s.startsWith('/') || s.startsWith('\\')) {
    return null;
  }
  return s;
}

export default function (req: { query: { path: string } }) {
  const raw = req.query.path;
  const safe = sanitizePath(raw);
  if (safe === null) return;
  return fs.readFileSync(safe);
}
