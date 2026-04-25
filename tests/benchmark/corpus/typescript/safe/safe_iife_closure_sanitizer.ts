// ts-iife-closure-001: top-level IIFE that wraps the request handler
// in a closure carrying a hardcoded sanitiser.  Engine must not fire
// `taint-unsanitised-flow` — the wrapped handler always passes its
// user-supplied input through `cleanInput` before reaching the sink.
import * as express from 'express';

interface QueryRequest {
  query: { q: string };
}

const app = express();

(function () {
  function cleanInput(s: string): string {
    return encodeURIComponent(s);
  }
  app.get('/search', (req: QueryRequest, res) => {
    const q = req.query.q;
    const safe = cleanInput(q);
    res.send('<p>Results for: ' + safe + '</p>');
  });
})();
