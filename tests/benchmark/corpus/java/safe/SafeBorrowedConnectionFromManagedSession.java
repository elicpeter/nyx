import liquibase.database.Database;
import liquibase.database.jvm.JdbcConnection;
import java.sql.PreparedStatement;

// Precision: a Liquibase changeset borrows its JDBC connection from the
// `Database` argument.  Liquibase owns and closes that connection at the end
// of the changelog run, so the changeset must NOT close it — a leak-at-exit
// finding on the borrowed connection is a false positive.  Receiver-type
// discrimination (`database` is typed `Database`, a borrowed owner) marks the
// acquire so neither `state-resource-leak` nor `cfg-resource-leak` fires.
//
// Distilled from openmrs
// api/src/main/java/org/openmrs/util/databasechange/BooleanConceptChangeSet.java:71.
public class SafeBorrowedConnectionFromManagedSession {
    public void execute(Database database) throws Exception {
        JdbcConnection connection = (JdbcConnection) database.getConnection();
        // The statement is closed via try-with-resources; only the borrowed
        // connection is left open, and Liquibase closes that itself.
        try (PreparedStatement pStmt = connection.prepareStatement(
                "UPDATE concept SET datatype_id = 4 WHERE datatype_id = 10")) {
            pStmt.executeUpdate();
        }
        // connection intentionally not closed: the Database owns it.
    }
}
