// ts-iife-closure-vuln-001: same IIFE shape as
// safe_iife_closure_sanitizer.ts but the closure forgets to apply
// `cleanInput`.  `taint-unsanitised-flow` should fire — the engine
// must follow taint through the IIFE wrapper into the handler scope.
import * as express from 'express';

interface QueryRequest {
  query: { q: string };
}

const app = express();

(function () {
  app.get('/search', (req: QueryRequest, res) => {
    const q = req.query.q;
    res.send('<p>Results for: ' + q + '</p>');
  });
})();
