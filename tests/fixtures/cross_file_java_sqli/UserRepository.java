import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

/**
 * Repository / DAO layer.
 *
 * SINK: executeQuery() with a concatenated, user-controlled string.
 * Called from UserController.java with an unsanitised HTTP parameter.
 *
 * A parameterised query (PreparedStatement / prepareStatement) would prevent
 * this; raw string concatenation does not.
 */
public class UserRepository {

    private static final String DB_URL = "jdbc:mysql://localhost/appdb";

    public void findByName(String name) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL);
        Statement stmt = conn.createStatement();

        // VULN: tainted `name` concatenated directly into SQL string
        stmt.executeQuery(
            "SELECT * FROM users WHERE username = '" + name + "'"
        );
    }
}
