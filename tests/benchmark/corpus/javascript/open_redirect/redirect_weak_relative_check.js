// Synthetic regression guard (CVE-2026-42259 class).
//
// A redirect gated only by a WEAK relative-URL check — `.includes("//")` /
// `.includes(":/")` substring tests, with no backslash normalisation — must
// still fire `taint-open-redirect`.  The engine must NOT mistake the weak
// form for a sound relative-URL confiner (which would require rejecting `//`
// by prefix and rejecting `scheme:`).
const express = require('express');
const app = express();

const is_relative_url = (url) => {
  return typeof url === "string" && !url.includes(":/") && !url.includes("//");
};

app.get('/go', (req, res) => {
  const next = req.query.next;
  if (is_relative_url(next)) {
    res.redirect(next);
  }
});
