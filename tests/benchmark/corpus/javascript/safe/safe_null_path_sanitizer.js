// js-safe-015: null-returning sanitiser with explicit `null` failure sentinel.
const fs = require('fs');

function sanitizePath(s) {
  if (s.includes('..') || s.startsWith('/') || s.startsWith('\\')) {
    return null;
  }
  return s;
}

function handler(req) {
  const raw = req.query.path;
  const safe = sanitizePath(raw);
  if (safe === null) return;
  return fs.readFileSync(safe);
}
