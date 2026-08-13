import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import org.hibernate.Session;

// Precision: a JDBC `PreparedStatement` opened on a `Connection` that is
// BORROWED from a managed session (`session.getConnection()`) and released via
// a static `closeQuietly` helper (not recognised as a `.close()` release).
// Per the JDBC contract, closing the Connection closes its Statements, and the
// managing Session closes the Connection — so the standalone `pstmt` leak is a
// false positive.  The owning `connection` is a locally-acquired resource
// (`getConnection`, flagged borrowed), so the derived `pstmt` leak is
// suppressed.  Distilled from sonarqube
// server/sonar-db-dao/src/main/java/org/sonar/db/source/FileSourceDao.java:66.
class SourceDao {
    List<String> selectLineHashes(Session session, String uuid) {
        Connection connection = session.getConnection();
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try {
            pstmt = connection.prepareStatement("SELECT hashes FROM sources WHERE uuid=?");
            pstmt.setString(1, uuid);
            rs = pstmt.executeQuery();
            return read(rs);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            closeQuietly(rs);
            closeQuietly(pstmt);
            closeQuietly(connection);
        }
    }
}
