import java.sql.Connection;
import java.sql.PreparedStatement;

// Recall guard: a `PreparedStatement` opened on a LONG-LIVED field connection
// (not a resource acquired in this body) genuinely accumulates — closing it is
// this body's responsibility because the field connection outlives the call.
// The derivation-edge suppression must NOT fire here: the receiver `connection`
// is a field, not a locally-acquired `getConnection` resource, so the `pstmt`
// leak is preserved.  Distilled from the openmrs helper shape where the
// connection is caller-owned but the opened statement is never closed.
class FieldConnectionDao {
    private Connection connection;

    void runUpdate(String sql) throws Exception {
        PreparedStatement pstmt = connection.prepareStatement(sql);
        pstmt.setString(1, "x");
        pstmt.executeUpdate();
        // pstmt never closed — real leak on a long-lived field connection.
    }
}
