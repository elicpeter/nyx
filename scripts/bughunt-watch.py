#!/usr/bin/env python3
"""Pretty-print tailer for bughunt overnight session logs.

Usage:
    ./scripts/bughunt-watch.py             # auto-pick newest log under nyx/logs/
    ./scripts/bughunt-watch.py LOG_FILE    # watch a specific log

Display style is inspired by the Claude Code CLI:

    ⏺ Read(/path/to/file.rs:1-50)
      ⎿  2.3KB · pub struct Foo { ...

    ⏺ Bash(cargo build --release)
      ⎿  847B · Compiling nyx v0.5.0 ...

      Streaming assistant text appears here, indented two spaces,
      with blank lines bracketing it from tool calls.

    ⏺ Edit(/path/to/file.rs)  [error]
      ⎿  ✗ Exit 1 · file not found

Ctrl+C to stop watching (does not affect the running loop).
Set NO_COLOR=1 to disable ANSI styling.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

LOG_DIR = Path("/Users/elipeter/nyx/logs")

COLOR = os.environ.get("NO_COLOR") is None and sys.stdout.isatty()


def style(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if COLOR else s


def dim(s: str) -> str:     return style("2", s)
def bold(s: str) -> str:    return style("1", s)
def cyan(s: str) -> str:    return style("36", s)
def green(s: str) -> str:   return style("32", s)
def yellow(s: str) -> str:  return style("33", s)
def red(s: str) -> str:     return style("31", s)
def magenta(s: str) -> str: return style("35", s)
def blue(s: str) -> str:    return style("34", s)


def term_cols() -> int:
    try:
        return shutil.get_terminal_size((120, 24)).columns
    except OSError:
        return 120


def truncate_one_line(s: str, width: int) -> str:
    """Single-line truncation. Replace newlines with ⏎."""
    s = s.replace("\n", " ⏎ ").replace("\r", "")
    if width <= 1:
        return ""
    if len(s) <= width:
        return s
    return s[: width - 1] + "…"


def pick_log() -> Path:
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    candidates = sorted(
        LOG_DIR.glob("bughunt-overnight-*.log"),
        key=lambda p: p.stat().st_mtime,
    )
    if not candidates:
        sys.exit(f"No bughunt-overnight-*.log found in {LOG_DIR}")
    return candidates[-1]


def follow(path: Path):
    """tail -f style line generator. Sleeps at EOF; reopens if file rotated."""
    while not path.exists():
        time.sleep(0.5)
    inode = path.stat().st_ino
    f = path.open("r")
    try:
        while True:
            line = f.readline()
            if line:
                yield line
                continue
            time.sleep(0.15)
            try:
                if path.stat().st_ino != inode:
                    f.close()
                    f = path.open("r")
                    inode = path.stat().st_ino
            except FileNotFoundError:
                pass
    finally:
        f.close()


# --------------------------------------------------------------------------
# Per-tool one-line input formatting
# --------------------------------------------------------------------------

def format_tool_args(tool: str, parsed) -> str:
    """One-line summary of a tool's input — the bit you actually want to see."""
    if not isinstance(parsed, dict):
        return json.dumps(parsed, separators=(",", ":"))

    if tool == "Read":
        path = parsed.get("file_path", "?")
        off = parsed.get("offset")
        lim = parsed.get("limit")
        if isinstance(off, int) and isinstance(lim, int):
            return f"{path}:{off}-{off + lim}"
        return path

    if tool in ("Edit", "Write", "NotebookEdit"):
        return parsed.get("file_path") or parsed.get("notebook_path") or "?"

    if tool == "Bash":
        return parsed.get("command", "?")

    if tool == "Glob":
        pat = parsed.get("pattern", "?")
        path = parsed.get("path", "")
        return f"{pat} in {path}" if path else pat

    if tool == "Grep":
        pat = parsed.get("pattern", "?")
        path = parsed.get("path", "")
        return f"'{pat}' in {path}" if path else f"'{pat}'"

    if tool == "TodoWrite":
        todos = parsed.get("todos", [])
        in_progress = [t.get("content", "") for t in todos if t.get("status") == "in_progress"]
        return f"{len(todos)} todos · {(in_progress[0] if in_progress else '')[:80]}"

    if tool == "ToolSearch":
        return parsed.get("query", "?")

    if tool == "Agent":
        desc = parsed.get("description", "")
        sub = parsed.get("subagent_type", "default")
        return f"{desc} [{sub}]"

    if tool == "Skill":
        return parsed.get("skill", "?")

    return json.dumps(parsed, separators=(",", ":"))


def render_tool_result(block: dict) -> tuple[str, str]:
    """Returns (size_str, first_line) for a tool_result content block."""
    content = block.get("content", "")
    if isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                parts.append(c.get("text", ""))
            elif isinstance(c, str):
                parts.append(c)
        text = "\n".join(parts)
    else:
        text = str(content) if content is not None else ""

    size = len(text)
    if size < 1024:
        size_str = f"{size}B"
    elif size < 1024 * 1024:
        size_str = f"{size / 1024:.1f}KB"
    else:
        size_str = f"{size / (1024 * 1024):.1f}MB"

    # First non-empty line
    first = ""
    for line in text.split("\n"):
        if line.strip():
            first = line
            break
    if not first and text:
        first = "(whitespace)"
    elif not text:
        first = "(empty)"

    return size_str, first


# --------------------------------------------------------------------------
# Display rendering
# --------------------------------------------------------------------------

def emit_tool_call(tool: str, parsed) -> None:
    """Render a tool call as: ⏺ ToolName(args)"""
    cols = term_cols()
    glyph = green("⏺")
    name = bold(tool)
    args = format_tool_args(tool, parsed)
    # Account for: "⏺ " (2) + tool + "(" (1) + args + ")" (1)
    overhead = 2 + len(tool) + 2  # plus newlines
    avail = max(20, cols - overhead - 2)  # -2 small safety margin
    truncated_args = truncate_one_line(args, avail)
    print(f"{glyph} {name}({dim(truncated_args)})")


def emit_tool_result(block: dict) -> None:
    """Render the result line: ⎿  size · first-line  (entire line dimmed)"""
    cols = term_cols()
    is_error = bool(block.get("is_error", False))
    size_str, first = render_tool_result(block)

    plain_prefix_len = 2 + 1 + 2 + (2 if is_error else 0) + len(size_str) + 3
    avail = max(20, cols - plain_prefix_len - 2)
    preview = truncate_one_line(first, avail)

    if is_error:
        line = "  " + red("⎿") + "  " + red("✗ ") + red(size_str) + red(" · ") + red(preview)
    else:
        # Whole line dimmed — pushes tool noise visually into the background
        line = "  " + dim("⎿  " + size_str + " · " + preview)
    print(line)


def emit_session_init(ev: dict) -> None:
    cols = term_cols()
    rule = "─" * min(cols - 2, 78)
    print()
    print(cyan(rule))
    sid = ev.get("session_id", "")[:8]
    model = ev.get("model", "")
    cwd = ev.get("cwd", "")
    print(cyan(f" session init  ") + dim(f"session={sid} model={model} cwd={cwd}"))
    print(cyan(rule))
    print()


def emit_session_done(ev: dict) -> None:
    cols = term_cols()
    rule = "─" * min(cols - 2, 78)
    subtype = ev.get("subtype", "")
    dur_ms = ev.get("duration_ms")
    cost = ev.get("total_cost_usd")
    turns = ev.get("num_turns")
    parts = []
    if turns is not None:
        parts.append(f"turns={turns}")
    if dur_ms is not None:
        parts.append(f"duration={dur_ms / 1000:.0f}s")
    if cost is not None:
        parts.append(f"cost=${cost:.3f}")
    parts.append(f"result={subtype}")
    print()
    print(cyan(rule))
    print(cyan(f" session done  ") + dim("  ".join(parts)))
    print(cyan(rule))
    print()


def emit_rate_limit(ev: dict) -> None:
    info = ev.get("rate_limit_info", {})
    status = info.get("status", "?")
    if status == "allowed":
        return  # don't spam — only show when actually limited
    print()
    print(yellow(f"⚠ rate-limit {status}: ") + dim(json.dumps(info, separators=(",", ":"))[:200]))
    print()


# --------------------------------------------------------------------------
# Main loop with a small state machine
# --------------------------------------------------------------------------

# State for the streaming pretty-printer:
#   IDLE          -> not inside a content block
#   IN_TEXT       -> currently streaming assistant text deltas to stdout
#   IN_TOOL_USE   -> buffering tool-input deltas; will emit on content_block_stop
STATE_IDLE = 0
STATE_IN_TEXT = 1
STATE_IN_TOOL_USE = 2


def main() -> None:
    log = pick_log()
    print(dim(f"watching: {log}"))
    print(dim("(Ctrl+C to stop watching — does not stop the loop)"))

    state = STATE_IDLE
    tool_name: str | None = None
    tool_input_buf = ""
    text_at_line_start = True   # True if next text_delta should be indented

    def end_text_if_open():
        """If we were streaming text, close the line and add a blank line after."""
        nonlocal state, text_at_line_start
        if state == STATE_IN_TEXT:
            sys.stdout.write("\n\n")  # close text line + blank line for breathing room
            sys.stdout.flush()
            state = STATE_IDLE
            text_at_line_start = True

    for raw in follow(log):
        line = raw.rstrip("\n")
        if not line.startswith("{"):
            # Banner / non-JSON text from the loop wrapper
            end_text_if_open()
            if line.strip():
                print(dim(line))
            else:
                print()
            continue

        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue

        t = ev.get("type")

        if t == "system":
            if ev.get("subtype") == "init":
                end_text_if_open()
                emit_session_init(ev)

        elif t == "stream_event":
            event = ev.get("event", {})
            etype = event.get("type")

            if etype == "content_block_start":
                cb = event.get("content_block", {})
                cb_type = cb.get("type")
                if cb_type == "tool_use":
                    end_text_if_open()
                    state = STATE_IN_TOOL_USE
                    tool_name = cb.get("name", "?")
                    tool_input_buf = ""
                elif cb_type == "text":
                    # If we were already in text (shouldn't happen) close it first
                    end_text_if_open()
                    # Blank line BEFORE the text block for breathing room
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    state = STATE_IN_TEXT
                    text_at_line_start = True
                # other content block types (thinking?) — ignore for now

            elif etype == "content_block_delta":
                delta = event.get("delta", {})
                dtype = delta.get("type")
                if dtype == "text_delta" and state == STATE_IN_TEXT:
                    text = delta.get("text", "")
                    if not text:
                        continue
                    # 2-space indent at start of each line for visual hierarchy
                    out = ""
                    for i, ch in enumerate(text):
                        if text_at_line_start:
                            out += "  "
                            text_at_line_start = False
                        out += ch
                        if ch == "\n":
                            text_at_line_start = True
                    sys.stdout.write(out)
                    sys.stdout.flush()
                elif dtype == "input_json_delta" and state == STATE_IN_TOOL_USE:
                    tool_input_buf += delta.get("partial_json", "")

            elif etype == "content_block_stop":
                if state == STATE_IN_TOOL_USE and tool_name is not None:
                    try:
                        parsed = json.loads(tool_input_buf) if tool_input_buf else {}
                    except json.JSONDecodeError:
                        parsed = tool_input_buf  # render as raw string
                    emit_tool_call(tool_name, parsed)
                    state = STATE_IDLE
                    tool_name = None
                    tool_input_buf = ""
                elif state == STATE_IN_TEXT:
                    # End the text block cleanly
                    end_text_if_open()

            elif etype == "message_stop":
                end_text_if_open()

            # message_start / message_delta — silent

        elif t == "user":
            end_text_if_open()
            content = ev.get("message", {}).get("content", [])
            for block in content:
                if block.get("type") == "tool_result":
                    emit_tool_result(block)

        elif t == "assistant":
            # Full assistant turn — already streamed via stream_event deltas.
            # Skip to avoid duplicating output.
            pass

        elif t == "result":
            end_text_if_open()
            emit_session_done(ev)

        elif t == "rate_limit_event":
            end_text_if_open()
            emit_rate_limit(ev)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(0)
    except BrokenPipeError:
        sys.exit(0)
