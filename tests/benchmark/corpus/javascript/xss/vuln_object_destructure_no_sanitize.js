// js-destructure-vuln-001: same destructuring shape as
// safe_object_destructure_sanitize.js but the sanitiser is removed.
// `taint-unsanitised-flow` should fire — the destructured `name` flows
// straight into a template-literal HTML sink with no encoding.
const express = require('express');
const app = express();

app.get('/profile', (req, res) => {
  const { name } = req.query;
  res.send(`<h1>Welcome, ${name}</h1>`);
});
