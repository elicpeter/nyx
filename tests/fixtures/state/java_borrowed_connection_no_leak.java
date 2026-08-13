import liquibase.database.Database;
import liquibase.database.jvm.JdbcConnection;
import java.sql.PreparedStatement;

// Precision: a Liquibase changeset borrows its JDBC connection from the
// `Database` argument.  Liquibase owns and closes that connection itself, so
// the changeset must NOT close it — flagging the borrowed connection as a
// leak-at-exit is a false positive.  Receiver-type discrimination
// (`database` is typed `Database`, a borrowed owner) suppresses the leak.
//
// Distilled from openmrs
// api/src/main/java/org/openmrs/util/databasechange/BooleanConceptChangeSet.java:71.
class BorrowedConnectionChangeSet {
    void execute(Database database) throws Exception {
        JdbcConnection connection = (JdbcConnection) database.getConnection();
        try (PreparedStatement pStmt = connection.prepareStatement(
                "UPDATE concept SET datatype_id = 4 WHERE datatype_id = 10")) {
            pStmt.executeUpdate();
        }
        // connection intentionally not closed: the Database owns it.
    }
}
