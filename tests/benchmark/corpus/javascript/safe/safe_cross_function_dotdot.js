// js-safe-016: cross-function bool-returning validator with rejection.
const fs = require('fs');

function validateNoDotdot(s) {
  return !s.includes('..') && !s.startsWith('/') && !s.startsWith('\\');
}

function handler(req) {
  const raw = req.query.path;
  if (!validateNoDotdot(raw)) return;
  return fs.readFileSync(raw);
}
