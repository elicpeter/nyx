def main():
    x = nyx_taint_source()
    nyx_dangerous_sink(x)
    y = nyx_pass_through(nyx_taint_source())
    nyx_dangerous_sink(nyx_sanitize(y))

main()
