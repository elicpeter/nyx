// java-safe-016: cross-function bool-returning validator with rejection.
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class SafeCrossFunctionDotdot {
    public static boolean validateNoDotdot(String s) {
        return !s.contains("..") && !s.startsWith("/") && !s.startsWith("\\");
    }

    public static void handle(String userPath) throws IOException {
        if (!validateNoDotdot(userPath)) {
            return;
        }
        Files.readAllBytes(Paths.get(userPath));
    }
}
