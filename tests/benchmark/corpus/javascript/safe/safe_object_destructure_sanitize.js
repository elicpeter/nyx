// js-destructure-sanitize-001: object destructuring at the handler
// boundary feeds the destructured field through `encodeURIComponent`
// before the HTML sink.  Engine must not fire `taint-unsanitised-flow`
// — encodeURIComponent percent-encodes HTML-significant characters,
// so the sink's HTML_ESCAPE cap is cleared.
const express = require('express');
const app = express();

app.get('/profile', (req, res) => {
  const { name } = req.query;
  const safe = encodeURIComponent(name);
  res.send(`<h1>Welcome, ${safe}</h1>`);
});
