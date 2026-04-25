// java-safe-015: Optional<String>-returning sanitiser with `.empty()` failure sentinel.
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;

public class SafeOptionalPathSanitizer {
    public static Optional<String> sanitizePath(String s) {
        if (s.contains("..") || s.startsWith("/") || s.startsWith("\\")) {
            return Optional.empty();
        }
        return Optional.of(s);
    }

    public static void handle(String userPath) throws IOException {
        Optional<String> safe = sanitizePath(userPath);
        if (!safe.isPresent()) return;
        Files.readAllBytes(Paths.get(safe.get()));
    }
}
