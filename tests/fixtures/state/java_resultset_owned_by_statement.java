import java.sql.*;

// Precision: a JDBC `ResultSet` obtained from `stmt.executeQuery()` is owned
// by the `Statement` that produced it.  Both `con` and `ps` are closed by the
// try-with-resources; per the JDBC contract closing `ps` closes its
// `ResultSet`, so `resultSet` is transitively closed even though it is never
// explicitly `.close()`-d.  No resource-leak finding should fire.
//
// Distilled from openmrs
// `api/src/main/java/org/openmrs/util/DatabaseUpdater.java:288`.
class Dao {
    boolean updatesRequired(java.util.function.Supplier<Connection> src) throws Exception {
        String stored = null;
        try (Connection con = src.get()) {
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
