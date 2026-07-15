import org.hibernate.Session;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

// Precision (real-repo distillation): a JDBC `PreparedStatement` opened on a
// `Connection` that is BORROWED from a managed `Session`
// (`session.getConnection()`) and released via a static `closeQuietly` helper
// the release detector does not recognise as a `.close()` call.  Per the JDBC
// contract, closing a `Connection` closes every `Statement` it produced, and
// the managing `Session` closes the `Connection` — so the standalone `pstmt`
// leak is a false positive.  The owning `connection` is a locally-acquired
// resource (a `getConnection` acquire), so the derived statement leak is
// suppressed at BOTH the `state-resource-leak` and `cfg-resource-leak` passes.
//
// Distilled from sonarqube
// server/sonar-db-dao/src/main/java/org/sonar/db/source/FileSourceDao.java:66
// and the sonarqube `Ce*Dao` connection-per-statement shape.  A statement on a
// long-lived field / parameter connection this body does not track is
// unaffected and still leaks (recall:
// tests/fixtures/state/java_statement_from_field_connection_leaks.java).
public class SafeStatementFromManagedConnection {
    public String selectHash(Session session, String uuid) {
        Connection connection = session.getConnection();
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pstmt = connection.prepareStatement("SELECT hash FROM file_sources WHERE uuid = ?");
            pstmt.setString(1, uuid);
            rs = pstmt.executeQuery();
            return rs.next() ? rs.getString(1) : null;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        } finally {
            closeQuietly(rs);
            closeQuietly(pstmt);
            closeQuietly(connection);
        }
    }
}
