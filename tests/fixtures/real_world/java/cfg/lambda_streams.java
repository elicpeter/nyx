import java.util.*;
import java.util.stream.*;

public class StreamProcessor {
    public List<String> filterUnsafe(List<String> inputs) {
        return inputs.stream()
            .filter(s -> !s.isEmpty())
            .map(s -> "SELECT * FROM users WHERE name = '" + s + "'")
            .collect(Collectors.toList());
    }

    public void processCommands(List<String> commands) {
        commands.forEach(cmd -> {
            try {
                Runtime.getRuntime().exec(cmd);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
}
