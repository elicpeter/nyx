// ─────────────────────────────────────────────────────────────────────────────
// examples/cross-file/main.rs — The caller
//
// This file calls functions from config.rs, sanitize.rs, and exec.rs.
// It never directly touches std::env, std::fs, or std::process — every
// source, sanitiser, and sink lives in another file.
//
// Nyx's two-pass cross-file taint analysis should:
//   • Pass 1: summarise config.rs, sanitize.rs, exec.rs
//   • Pass 2: resolve calls in main.rs against those summaries
//
// ─────────────────────────────────────────────────────────────────────────────
//
//  EXPECTED NYX OUTPUT
//  ===================
//
//  examples/cross-file/main.rs
//    12:5   [High]  taint-unsanitised-flow       ← case_1_direct_source_to_sink
//    22:5   [High]  taint-unsanitised-flow       ← case_3_wrong_sanitiser
//    34:5   [High]  taint-unsanitised-flow       ← case_5_passthrough_preserves_taint
//    40:5   [High]  taint-unsanitised-flow       ← case_6_taint_through_branch
//    50:5   [High]  taint-unsanitised-flow       ← case_8_source_and_sink_same_fn
//
//  examples/cross-file/exec.rs
//    30:5   [High]  taint-unsanitised-flow       ← log_and_execute internal vuln
//
//  NO findings expected for:
//    case_2  (correct sanitiser applied)
//    case_4  (correct html sanitiser applied)
//    case_7  (sanitised before branch)
//
// ─────────────────────────────────────────────────────────────────────────────

// ─── Case 1: Direct source → sink (UNSAFE) ──────────────────────────────────
//
//   get_user_command() returns tainted(ALL)
//   run_command() is a sink(SHELL_ESCAPE)
//   No sanitiser in between → FINDING
//
fn case_1_direct_source_to_sink() {
    let cmd = get_user_command();           // tainted(ALL) via cross-file source
    run_command(&cmd);                      // FINDING: taint reaches shell sink
}

// ─── Case 2: Correctly sanitised (SAFE) ─────────────────────────────────────
//
//   get_user_command() returns tainted(ALL)
//   sanitize_shell() strips SHELL_ESCAPE
//   run_command() sinks SHELL_ESCAPE → bit is gone → no finding
//
fn case_2_sanitised_before_sink() {
    let cmd = get_user_command();           // tainted(ALL)
    let safe = sanitize_shell(&cmd);        // SHELL_ESCAPE bit stripped
    run_command(&safe);                     // SAFE — no finding
}

// ─── Case 3: Wrong sanitiser for the sink (UNSAFE) ──────────────────────────
//
//   get_user_command() returns tainted(ALL)
//   sanitize_html() strips HTML_ESCAPE — but NOT SHELL_ESCAPE
//   run_command() sinks SHELL_ESCAPE → bit still set → FINDING
//
fn case_3_wrong_sanitiser() {
    let cmd = get_user_command();           // tainted(ALL)
    let wrong = sanitize_html(&cmd);        // strips HTML_ESCAPE only
    run_command(&wrong);                    // FINDING: SHELL_ESCAPE still set
}

// ─── Case 4: Correct HTML sanitiser (SAFE) ──────────────────────────────────
//
//   load_template() returns tainted(ALL) from file read
//   sanitize_html() strips HTML_ESCAPE
//   render_page() sinks HTML_ESCAPE → bit is gone → no finding
//
fn case_4_html_sanitised() {
    let tpl = load_template("page.html");   // tainted(ALL) via cross-file source
    let safe = sanitize_html(&tpl);         // HTML_ESCAPE bit stripped
    render_page(&safe);                     // SAFE — no finding
}

// ─── Case 5: Passthrough preserves taint (UNSAFE) ───────────────────────────
//
//   get_user_command() returns tainted(ALL)
//   passthrough() propagates taint unchanged (propagates_taint = true)
//   run_command() sinks SHELL_ESCAPE → still tainted → FINDING
//
fn case_5_passthrough_preserves_taint() {
    let cmd = get_user_command();           // tainted(ALL)
    let same = passthrough(&cmd);           // taint flows through
    run_command(&same);                     // FINDING: still tainted
}

// ─── Case 6: Taint flows through only one branch (UNSAFE) ───────────────────
//
//   One branch sanitises, the other does not.
//   The unsanitised branch reaches the sink → FINDING on that path.
//
fn case_6_taint_through_branch() {
    let cmd = get_user_command();           // tainted(ALL)
    if cmd.len() > 10 {
        run_command(&cmd);                  // FINDING: unsanitised path
    } else {
        let safe = sanitize_shell(&cmd);
        run_command(&safe);                 // SAFE path
    }
}

// ─── Case 7: Sanitised before branch (SAFE) ─────────────────────────────────
//
//   Sanitisation happens before the branch → both paths are clean.
//
fn case_7_sanitised_before_branch() {
    let cmd = get_user_command();           // tainted(ALL)
    let safe = sanitize_shell(&cmd);        // SHELL_ESCAPE stripped
    if safe.len() > 10 {
        run_command(&safe);                 // SAFE
    } else {
        run_command(&safe);                 // SAFE
    }
}

// ─── Case 8: Source-and-sink function (UNSAFE) ──────────────────────────────
//
//   log_and_execute() is both:
//     • a SINK(SHELL_ESCAPE) on its cmd parameter
//     • a SOURCE(ALL) in its return value (reads env var)
//
//   Passing tainted data to it → FINDING for the sink.
//   Its return value is freshly tainted, but we don't pass it anywhere
//   dangerous here — so only one finding.
//
fn case_8_source_and_sink_same_fn() {
    let cmd = get_user_command();           // tainted(ALL)
    let _log = log_and_execute(&cmd);       // FINDING: tainted arg hits shell sink
    // _log is now tainted(ALL) from log_and_execute's source behaviour,
    // but we don't use it — no second finding.
}

fn main() {
    case_1_direct_source_to_sink();
    case_2_sanitised_before_sink();
    case_3_wrong_sanitiser();
    case_4_html_sanitised();
    case_5_passthrough_preserves_taint();
    case_6_taint_through_branch();
    case_7_sanitised_before_branch();
    case_8_source_and_sink_same_fn();
}
