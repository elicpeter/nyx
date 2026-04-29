function main(): void {
    const x: string = nyx_taint_source();
    nyx_dangerous_sink(x);
    const y: string = nyx_sanitize(nyx_taint_source());
    nyx_dangerous_sink(y);
}
main();
