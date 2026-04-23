/**
 * Phase 11 regression: tainted receiver flowing through chained
 * zero-arg builder methods and into Runtime.exec.
 *
 * The receiver-fallback path in ssa_transfer's call handling is
 * expected to thread taint through `tainted.trim().toLowerCase()` —
 * neither method takes arguments, so the taint travels purely through
 * the receiver channel.  This fixture pins that behaviour so the
 * Phase 11 heap-aliasing changes do not regress it.
 */
public class Main {
    public static void main(String[] args) throws Exception {
        String tainted = System.getenv("INPUT");     // SOURCE
        String result = tainted.trim().toLowerCase();
        Runtime.getRuntime().exec(result);           // SINK
    }
}
