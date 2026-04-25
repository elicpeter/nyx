import javax.naming.InitialContext;

public class SafeSpringPatterns {
    private Object jdbcTemplate;
    private Object entityManager;

    public void safeQuery() {
        Object result = jdbcTemplate.query("SELECT * FROM users WHERE id = ?");
    }

    public void safeJpql() {
        Object result = entityManager.createQuery("SELECT u FROM User u");
    }

    public void safeLookup() throws Exception {
        InitialContext ctx = new InitialContext();
        Object ds = ctx.lookup("java:comp/env/jdbc/mydb");
    }
}
