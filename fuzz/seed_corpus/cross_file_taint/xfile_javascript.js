function main() {
    let x = nyx_taint_source();
    nyx_dangerous_sink(x);
    let y = nyx_pass_through(nyx_taint_source());
    nyx_dangerous_sink(nyx_sanitize(y));
}
main();
