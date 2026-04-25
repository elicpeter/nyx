// ts-safe-016: cross-function bool-returning validator with rejection.
import * as fs from 'fs';

function validateNoDotdot(s: string): boolean {
  return !s.includes('..') && !s.startsWith('/') && !s.startsWith('\\');
}

export default function (req: { query: { path: string } }) {
  const raw = req.query.path;
  if (!validateNoDotdot(raw)) return;
  return fs.readFileSync(raw);
}
