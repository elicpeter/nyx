// java-safe-014: direct-return path sanitiser using `.contains` / `.startsWith`.
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class SafeDirectPathSanitizer {
    public static String sanitizePath(String s) {
        if (s.contains("..") || s.startsWith("/") || s.startsWith("\\")) {
            return "";
        }
        return s;
    }

    public static void handle(String userPath) throws IOException {
        String safe = sanitizePath(userPath);
        Files.readAllBytes(Paths.get(safe));
    }
}
