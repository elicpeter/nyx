import java.sql.*;
import java.util.*;
import java.util.stream.*;

public class StreamProcessor {
    public List<String> filterUnsafe(Statement stmt, List<String> inputs) throws SQLException {
        return inputs.stream()
            .filter(s -> !s.isEmpty())
            .map(s -> {
                try {
                    stmt.executeQuery("SELECT * FROM users WHERE name = '" + s + "'");
                } catch (SQLException e) {
                }
                return s;
            })
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
