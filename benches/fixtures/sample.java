import java.io.IOException;

public class Sample {
    public static String getEnv() {
        return System.getenv("DB_PASSWORD");
    }

    public static String sanitize(String input) {
        return input.replaceAll("[<>&]", "");
    }

    public static void executeCommand(String cmd) throws IOException {
        Runtime.getRuntime().exec(cmd);
    }

    public static void safeFlow() throws IOException {
        String val = getEnv();
        String clean = sanitize(val);
        System.out.println(clean);
    }

    public static void unsafeFlow() throws IOException {
        String val = getEnv();
        executeCommand(val);
    }

    public static void main(String[] args) throws IOException {
        safeFlow();
        unsafeFlow();
    }
}
