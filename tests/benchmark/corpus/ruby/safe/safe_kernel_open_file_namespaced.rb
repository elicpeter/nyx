# Negative regression for the Ruby `=open` exact-matcher.  `File.open`
# (and `IO.open`, `URI.open`) must not fire the bare-`open` CMDI rule.
# Each namespaced form has non-piping semantics, so even with attacker-
# controlled paths the CMDI vector is closed.  Pairs with
# `cmdi/cmdi_kernel_open.rb`.
#
# A hardcoded filename is used so this file is also a clean TN at the
# benchmark level — the existing `File.open` FILE_IO matcher is
# orthogonal to the CMDI regression we're guarding here, so we don't
# want any taint flow either way.
def read_log
  filename = "/var/log/audit.log"
  File.open(filename, "r") do |inf|
    inf.each_line { |l| puts l }
  end
end
