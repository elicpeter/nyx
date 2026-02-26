# JavaScript Rules

JavaScript has the most complete taint label coverage alongside Rust. Nyx detects code execution, XSS, prototype pollution, command injection, and weak crypto.

## Taint Sources

| Function | Capability | Source Kind |
|----------|-----------|-------------|
| `document.location`, `window.location` | `all` | UserInput |
| `req.body`, `req.query`, `req.params` | `all` | UserInput |
| `req.headers`, `req.cookies` | `all` | UserInput |
| `process.env` | `all` | EnvironmentConfig |

## Taint Sinks

| Function | Required Capability |
|----------|-------------------|
| `eval` | `SHELL_ESCAPE` |
| `innerHTML` | `HTML_ESCAPE` |
| `location.href`, `window.location.href` | `URL_ENCODE` |
| `child_process.exec`, `child_process.execSync` | `SHELL_ESCAPE` |
| `child_process.spawn` | `SHELL_ESCAPE` |

## Taint Sanitizers

| Function | Strips Capability |
|----------|------------------|
| `JSON.parse` | `JSON_PARSE` |
| `encodeURIComponent`, `encodeURI` | `URL_ENCODE` |
| `DOMPurify.sanitize` | `HTML_ESCAPE` |

> **Note:** Anonymous function expressions and arrow functions passed as callback arguments (e.g., Express `app.get('/path', function(req, res) { ... })`) are automatically walked as separate function scopes for taint analysis. Each anonymous function gets a unique scope identifier to prevent cross-function taint leakage.

---

## AST Pattern Rules

### Code Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `js.code_exec.eval` | High | A | `eval()` — dynamic code execution |
| `js.code_exec.new_function` | High | A | `new Function()` — eval equivalent |
| `js.code_exec.settimeout_string` | Medium | A | `setTimeout`/`setInterval` with string argument |

### XSS Sinks

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `js.xss.document_write` | Medium | A | `document.write()` / `document.writeln()` |
| `js.xss.outer_html` | Medium | A | Assignment to `.outerHTML` |
| `js.xss.insert_adjacent_html` | Medium | A | `insertAdjacentHTML()` |
| `js.xss.location_assign` | Medium | A | Assignment to `location`/`location.href` — open redirect |
| `js.xss.cookie_write` | Medium | A | Write to `document.cookie` |

### Prototype Pollution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `js.prototype.proto_assignment` | Medium | A | Assignment to `__proto__` |
| `js.prototype.extend_object` | Medium | A | Assignment to `Object.prototype.*` |

### Weak Crypto

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `js.crypto.weak_hash` | Low | A | `crypto.createHash("md5"/"sha1")` |
| `js.crypto.math_random` | Low | A | `Math.random()` — not cryptographically secure |

### Insecure Transport

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `js.transport.fetch_http` | Low | A | `fetch("http://...")` — plaintext HTTP |

---

## Examples

### `js.code_exec.eval` — Dynamic code execution

**Vulnerable:**
```javascript
const code = req.query.code;
eval(code);  // Remote code execution
```

**Safe alternative:**
```javascript
// Use a sandboxed interpreter or avoid eval entirely
const allowed = { add: (a, b) => a + b };
const result = allowed[req.query.operation]?.(req.query.a, req.query.b);
```

### `js.xss.document_write` — XSS sink

**Vulnerable:**
```javascript
document.write("<h1>" + userName + "</h1>");
```

**Safe alternative:**
```javascript
const el = document.createElement("h1");
el.textContent = userName;
document.body.appendChild(el);
```

### `js.prototype.proto_assignment` — Prototype pollution

**Vulnerable:**
```javascript
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];  // If key is "__proto__", pollutes prototype
    }
}
```

**Safe alternative:**
```javascript
function merge(target, source) {
    for (let key in source) {
        if (key === "__proto__" || key === "constructor") continue;
        target[key] = source[key];
    }
}
```

### Taint: `req.body` → `eval()`

**Finding:**
```
[HIGH]   taint-unsanitised-flow (source 2:18)  src/handler.js:3:5
         Source: req.body at 2:18
         Sink: eval()
         Score: 78
```
