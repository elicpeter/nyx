public class Main {
    public static void main(String[] args) {
        String x = nyx_taint_source();
        nyx_dangerous_sink(x);
        String y = nyx_sanitize(nyx_taint_source());
        nyx_dangerous_sink(y);
    }
}
