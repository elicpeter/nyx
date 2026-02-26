# TypeScript Rules

TypeScript rules mirror JavaScript patterns plus TypeScript-specific type-safety escape detectors. Taint labels are shared with JavaScript (see [JavaScript Rules](javascript.md)).

---

## AST Pattern Rules

### Code Execution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `ts.code_exec.eval` | High | A | `eval()` — dynamic code execution |
| `ts.code_exec.new_function` | High | A | `new Function()` — eval equivalent |
| `ts.code_exec.settimeout_string` | Medium | A | `setTimeout`/`setInterval` with string argument |

### XSS Sinks

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `ts.xss.document_write` | Medium | A | `document.write()` / `document.writeln()` |
| `ts.xss.outer_html` | Medium | A | Assignment to `.outerHTML` |
| `ts.xss.insert_adjacent_html` | Medium | A | `insertAdjacentHTML()` |
| `ts.xss.location_assign` | Medium | A | Assignment to `location`/`location.href` |
| `ts.xss.cookie_write` | Low | A | Write to `document.cookie` |

### Prototype Pollution

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `ts.prototype.proto_assignment` | Medium | A | Assignment to `__proto__` |

### Weak Crypto

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `ts.crypto.math_random` | Low | A | `Math.random()` — not cryptographically secure |

### Code Quality (TypeScript-specific)

| Rule ID | Severity | Tier | Description |
|---------|----------|------|-------------|
| `ts.quality.any_annotation` | Low | A | Type annotation of `any` — disables type checking |
| `ts.quality.as_any` | Low | A | Type assertion `as any` — type-safety escape hatch |

---

## Examples

### `ts.quality.any_annotation` — `any` type

**Flagged:**
```typescript
function process(data: any) {  // ts.quality.any_annotation
    data.whatever();  // No type checking
}
```

**Safe alternative:**
```typescript
interface UserData { name: string; email: string; }
function process(data: UserData) {
    console.log(data.name);
}
```

### `ts.quality.as_any` — Type assertion escape

**Flagged:**
```typescript
const result = someValue as any;  // ts.quality.as_any
result.nonexistentMethod();
```

**Safe alternative:**
```typescript
if (isValidType(someValue)) {
    const result = someValue as KnownType;
    result.knownMethod();
}
```
