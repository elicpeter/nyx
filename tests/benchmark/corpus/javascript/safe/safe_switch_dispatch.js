// js-switch-dispatch-001: tainted dispatch via an explicit allowlist
// check.  When `req.query.action` is in the frozen allowlist, the
// engine's existing `AllowlistCheck` validation marks the value as
// validated; otherwise the handler returns "denied".  The taint engine
// must therefore not fire `taint-unsanitised-flow` on the `exec` sink.
const express = require('express');
const { exec } = require('child_process');
const app = express();

const ALLOWED = ['ls -la', 'whoami', 'pwd'];

app.get('/run', (req, res) => {
  const action = req.query.action;
  if (!ALLOWED.includes(action)) return res.send('denied');
  exec(action, (err, stdout) => res.send(stdout));
});
