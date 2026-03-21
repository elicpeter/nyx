# AST Pattern Matching

## Summary

AST patterns are tree-sitter queries that match specific structural code constructs. They are the simplest and fastest detector family -- no dataflow, no CFG, just structural presence. A match means the dangerous construct exists in the code; it does not prove the code is exploitable.

AST patterns run in all analysis modes, including `--mode ast` (where they are the only active detector).

## Rule IDs

Pattern rule IDs follow the format `<lang>.<category>.<specific>`:

```
rs.memory.transmute
js.code_exec.eval
py.deser.pickle_loads
c.memory.gets
java.sqli.execute_concat
```

See the [Rule Reference](../rules/index.md) for a complete listing per language.

## Pattern Tiers

| Tier | Meaning | Examples |
|------|---------|---------|
| **A** | Structural presence alone is high-signal | `gets()`, `eval()`, `pickle.loads()`, `mem::transmute` |
| **B** | Query includes a heuristic guard | SQL `execute` with concatenated arg, `printf(var)` with non-literal format |

Tier B patterns use additional tree-sitter predicates to reduce false positives. For example, `java.sqli.execute_concat` only fires when `executeQuery()` receives a `binary_expression` (string concatenation) as its argument, not when it receives a literal or parameter placeholder.

## What It Detects

### By category

| Category | What it matches | Example languages |
|----------|----------------|-------------------|
| **CommandExec** | Shell command execution functions | C (`system`), Python (`os.system`), Ruby (backticks) |
| **CodeExec** | Dynamic code evaluation | JS (`eval`, `new Function()`), Python (`exec`), PHP (`eval`) |
| **Deserialization** | Unsafe object deserialization | Java (`readObject`), Python (`pickle.loads`), Ruby (`Marshal.load`) |
| **SqlInjection** | SQL with string concatenation | Java, Go, Python, PHP (Tier B heuristic) |
| **PathTraversal** | File inclusion with variable path | PHP (`include $var`) |
| **Xss** | XSS sink functions | JS (`document.write`, `outerHTML`), Java (`getWriter().print`) |
| **Crypto** | Weak cryptographic algorithms | All languages (`md5`, `sha1`, `Math.random()`) |
| **Secrets** | Hardcoded credentials | Go (variable name matching) |
| **InsecureTransport** | Unencrypted communication | Go (`InsecureSkipVerify`), JS (`fetch("http://")`) |
| **Reflection** | Dynamic class/method dispatch | Java (`Class.forName`, `Method.invoke`), Ruby (`send`, `constantize`) |
| **MemorySafety** | Memory safety violations | Rust (`transmute`, `unsafe`), C (`gets`, `strcpy`, `sprintf`) |
| **Prototype** | Prototype pollution | JS/TS (`__proto__` assignment) |
| **CodeQuality** | Panic/abort/type-safety issues | Rust (`unwrap`, `panic!`), TS (`as any`) |

## What It Cannot Detect

- **Dataflow**: Patterns don't track whether the dangerous function receives tainted input. `eval("hello")` (safe) and `eval(userInput)` (dangerous) both match `js.code_exec.eval`.
- **Context**: Patterns don't understand whether the code is reachable, guarded, or inside a test.
- **Semantics**: `strcpy(dst, src)` always matches -- it cannot determine buffer sizes.
- **Indirect calls**: Function pointers, dynamic dispatch, and aliased references are invisible.

## Common False Positives

| Scenario | Why it fires | Mitigation |
|----------|-------------|------------|
| `eval()` with a hardcoded string literal | Pattern matches structural presence | Taint analysis won't flag this -- use `--mode cfg` for fewer false positives |
| `unsafe` block in Rust with sound justification | All unsafe blocks match | Filter with `--severity ">=MEDIUM"` (unsafe_block is Medium) |
| `.unwrap()` in test code | Acceptable in tests | Default non-prod downgrade reduces severity |
| `md5()` used for checksums (not security) | Pattern doesn't know usage intent | Filter Low severity or add to exclusions |
| SQL concatenation with trusted data | Tier B heuristic can't verify data source | Taint analysis is more precise here |

## Common False Negatives

| Scenario | Why it's missed |
|----------|----------------|
| `eval` called via alias (`let e = eval; e(input)`) | Pattern matches the identifier `eval`, not the resolved function |
| Dangerous function in a macro expansion | Tree-sitter parses the macro call, not the expansion |
| SQL injection via ORM query builder | No pattern for ORM-specific query building |
| Imported function under different name | `from os import system as s; s(cmd)` -- pattern looks for `system` |

## Confidence Levels

Every AST pattern has an explicit confidence level that reflects how likely the match represents a real issue:

| Level | Meaning | Typical use |
|-------|---------|-------------|
| **High** | Strong structural evidence that the code is dangerous. The matched construct is inherently unsafe or has no safe usage. | `gets()`, `pickle.loads()`, `eval()` with no guard |
| **Medium** | Likely issue, but context may change the assessment. Heuristic guards reduce false positives but cannot eliminate them. | SQL concatenation (Tier B), `unsafe` blocks, `exec` calls |
| **Low** | Heuristic match. The pattern flags a construct that *may* indicate a problem but frequently appears in safe code. Requires manual review. | Weak crypto for checksums, `.unwrap()` in non-test code, `Math.random()` |

Confidence flows into JSON and SARIF output alongside severity and rank score. Use `--min-confidence medium` (or `output.min_confidence = "medium"` in config) to filter out low-confidence matches.

## Confidence Signals

| Signal | Meaning |
|--------|---------|
| **Tier A** | High confidence -- the function itself is dangerous |
| **Tier B** | Moderate confidence -- heuristic guard reduces false positives |
| **High severity** | Critical vulnerability class (command exec, deserialization) |
| **Low severity** | Informational (weak crypto, code quality) |
| **Non-prod path** | Finding in test/vendor code -- downgraded by default |

## Tuning and Noise Controls

### Severity filtering

```bash
# Skip code-quality and weak-crypto findings
nyx scan . --severity ">=MEDIUM"

# Only critical findings
nyx scan . --severity HIGH
```

### Use taint for precision

```bash
# Taint-only mode: only report findings with confirmed dataflow
nyx scan . --mode cfg
```

### Exclude directories

```toml
[scanner]
excluded_directories = ["node_modules", "vendor", "generated"]
```

## Examples

### Tier A -- structural presence

**C: Banned function**
```c
char buf[64];
gets(buf);  // c.memory.gets -- always dangerous, no safe usage
```

**Python: Unsafe deserialization**
```python
import pickle
data = pickle.loads(user_input)  # py.deser.pickle_loads
```

### Tier B -- heuristic-guarded

**Java: SQL concatenation**
```java
// Fires: concatenated argument
stmt.executeQuery("SELECT * FROM users WHERE id=" + userId);
// java.sqli.execute_concat

// Does NOT fire: parameterized query
stmt.executeQuery(preparedSql);
```

**C: Format string**
```c
// Fires: variable as first argument
printf(user_input);  // c.memory.printf_no_fmt

// Does NOT fire: literal format string
printf("%s", user_input);
```
