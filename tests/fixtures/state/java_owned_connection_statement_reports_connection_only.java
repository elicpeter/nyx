import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;

// Invariant + recall: an OWNED connection (`DriverManager.getConnection`) that
// is never closed is a real leak, and it is the single actionable root — the
// statement derived from it would be closed transitively once the connection
// is closed.  So the engine reports the `conn` leak (recall preserved,
// `DriverManager` is not a borrowed owner) and suppresses the redundant `ps`
// statement leak whose owning connection is a locally-acquired resource.
// Mirrors the JDBC `ResultSet`-owned-by-`Statement` redundancy rule one level
// up the ownership chain.
class OwnedConnectionDao {
    void run(String url, String sql) throws Exception {
        Connection conn = DriverManager.getConnection(url);
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.executeUpdate();
        // Neither closed: `conn` is the reported leak, `ps` is redundant.
    }
}
