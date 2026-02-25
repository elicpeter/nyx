/*!
EXPECTED OUTPUT (high-level):

1) cfg-unguarded-sink (High / High confidence)
   - In handle_request(): user input from std::env::var("INPUT") flows to std::process::Command::new("sh").arg(&input)
   - No dominating SHELL_ESCAPE sanitizer or validation guard for that value.
   - This should rank very high in scoring (entry-point-ish name + close to entry + shell sink).

2) cfg-auth-gap (High / Medium confidence)
   - handle_request() looks like an entry-point (name matches handle_*)
   - Contains a shell sink without an auth guard (require_auth / is_authenticated / is_admin etc.)

3) cfg-resource-leak (Medium / High or Medium confidence)
   - alloc_then_return_leak(): malloc without free on an early return path.

4) cfg-unreachable-sanitizer or cfg-unreachable-guard (Medium/Low)
   - unreachable_sanitizer(): sanitizer call in unreachable block.

5) taint / dataflow (existing BFS taint engine):
   - should detect at least one taint finding for:
       env::var source -> Command sink
   - should NOT flag safe_shell() because it uses shell_escape::unix::escape(&input) and passes `safe`.

Notes:
- This fixture intentionally contains both vulnerable and safe patterns, plus unreachable code and resource misuse,
  to exercise cfg_analysis::{unreachable, guards, auth, resources, scoring}.
*/

use std::process::Command;

// ─── CFG: Entry-point-ish + unguarded sink + auth gap ─────────────────────────────

pub fn handle_request() {
  // Source (Cap::all)
  let input = std::env::var("INPUT").unwrap();

  // Vulnerable sink (Cap::SHELL_ESCAPE)
  Command::new("sh").arg(&input).status().unwrap();
}

// ─── CFG: Guarded sink (should NOT produce cfg-unguarded-sink) ────────────────────

pub fn safe_shell() {
  let input = std::env::var("INPUT").unwrap();

  // Sanitizer (Cap::SHELL_ESCAPE)
  let safe = shell_escape::unix::escape(&input);

  // Sink, but guarded by dominating sanitizer
  Command::new("sh").arg(&safe).status().unwrap();
}

// ─── CFG: Unreachable sanitizer (should report unreachable sanitizer/guard) ───────

pub fn unreachable_sanitizer() {
  let input = std::env::var("INPUT").unwrap();

  return;

  // This block is unreachable; should produce an unreachable finding for sanitizer call.
  let _safe = shell_escape::unix::escape(&input);
}

// ─── CFG: Resource misuse (malloc without free on some exit path) ─────────────────

extern "C" {
  fn malloc(size: usize) -> *mut u8;
  fn free(ptr: *mut u8);
}

pub fn alloc_then_return_leak(flag: bool) {
  unsafe {
    let p = malloc(128);

    // Early return leaks `p` on this path.
    if flag {
      return;
    }

    free(p);
  }
}

// ─── Extra: HTML sink labeling sanity (optional) ──────────────────────────────────

// `sink_html` is a test marker recognized as Sink(HTML_ESCAPE) by the label rules.
// In real code this would be something like response.body(), template.render(), etc.
fn sink_html(_s: &str) {}

pub fn html_print() {
  let raw = std::env::var("HTML").unwrap();
  sink_html(&raw);
}

pub fn html_print_sanitized() {
  let raw = std::env::var("HTML").unwrap();
  let safe = html_escape::encode_safe(&raw);
  sink_html(&safe);
}