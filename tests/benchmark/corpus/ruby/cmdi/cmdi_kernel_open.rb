# Synthetic regression for the Ruby `Kernel#open` CMDI gap surfaced by
# CVE-2020-8130 (rake `Rake::FileList#egrep`).  Bare `open(path)`
# interprets a path beginning with `|` as a shell command —
# `open("|cmd")` runs `cmd` and pipes its output into the block.
# Pinned via the `=open` exact-matcher in `src/labels/ruby.rs` so a
# refactor that drops the bare-form distinction (e.g. demotes the rule
# back to a generic suffix matcher) re-fires on `File.open` and breaks
# this test.
def grep_logs(params)
  filename = params[:file]
  open(filename, "r") do |inf|
    inf.each_line { |l| puts l }
  end
end
