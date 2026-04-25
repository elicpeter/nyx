// js-safe-014: direct-return path sanitiser using `.includes`/`.startsWith`.
const fs = require('fs');

function sanitizePath(s) {
  if (s.includes('..') || s.startsWith('/') || s.startsWith('\\')) {
    return '';
  }
  return s;
}

function handler(req) {
  const raw = req.query.path;
  const safe = sanitizePath(raw);
  return fs.readFileSync(safe);
}
