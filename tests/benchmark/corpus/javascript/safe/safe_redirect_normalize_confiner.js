// Synthetic precision guard (CVE-2026-42259 class).
//
// A redirect through a behaviour-recognised relative-URL confiner —
// normalises backslashes, then rejects protocol-relative (`//`) and any
// `scheme:` URL before returning the confined value — must be silent on both
// the taint layer and `cfg-unguarded-sink`.
const express = require('express');
const app = express();

const normalize_relative_url = (url) => {
  if (typeof url !== "string") return null;
  const normalised = url.replace(/\\/g, "/").trimStart();
  if (normalised.startsWith("//")) return null;
  if (/^[a-zA-Z][a-zA-Z0-9+\-.]*:/.test(normalised)) return null;
  return normalised;
};

app.get('/go', (req, res) => {
  const dest = normalize_relative_url(req.query.next);
  if (dest !== null) res.redirect(dest);
});
