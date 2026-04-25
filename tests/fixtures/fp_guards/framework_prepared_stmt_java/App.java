// FP GUARD — framework-safe pattern (JDBC PreparedStatement).
//
// The tainted request parameter is bound through setString on a
// PreparedStatement.  The database driver parameterises the value,
// so no SQL injection surface remains.  A precise analyser must
// not surface a taint-unsanitised-flow on the executeQuery call.
//
// Expected: NO taint-unsanitised-flow finding.
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

public class App {
    public ResultSet lookup(HttpServletRequest req, Connection conn) throws Exception {
        String name = req.getParameter("name");                        // tainted
        PreparedStatement ps = conn.prepareStatement(
            "SELECT id FROM users WHERE name = ?"
        );
        ps.setString(1, name);                                         // parameterised
        return ps.executeQuery();
    }
}
