import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.function.Supplier;

// Precision (real-repo distillation): a JDBC `ResultSet` obtained from
// `stmt.executeQuery()` is owned by the `Statement` that produced it.  Both
// `con` and `ps` are closed by the enclosing try-with-resources; per the JDBC
// contract closing `ps` closes its `ResultSet`, so `resultSet` is
// transitively closed even though it is never explicitly `.close()`-d.  No
// resource-leak finding (`state-resource-leak` / `cfg-resource-leak` /
// `state-resource-leak-possible`) should fire.
//
// Distilled from openmrs
// api/src/main/java/org/openmrs/util/DatabaseUpdater.java:288 and sonarqube
// server/.../ExportLineHashesStep.java:75.
public class SafeResultSetOwnedByStatement {
    public boolean updatesRequired(Supplier<Connection> source) throws Exception {
        String stored = null;
        try (Connection con = source.get()) {
            try (PreparedStatement ps = con.prepareStatement(
                    "SELECT property_value FROM global_property WHERE property = ?")) {
                ps.setString(1, "core.version");
                ResultSet resultSet = ps.executeQuery();
                if (resultSet.next()) {
                    stored = resultSet.getString(1);
                }
            }
        }
        return stored != null;
    }
}
