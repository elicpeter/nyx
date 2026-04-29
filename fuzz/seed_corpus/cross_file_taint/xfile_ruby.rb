def main
  x = nyx_taint_source
  nyx_dangerous_sink(x)
  y = nyx_sanitize(nyx_taint_source)
  nyx_dangerous_sink(y)
end
main
