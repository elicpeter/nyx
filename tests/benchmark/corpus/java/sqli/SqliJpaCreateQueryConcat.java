import javax.persistence.EntityManager;

// Vulnerable counterpart to SafeJpaParameterizedExecute.  When the SQL
// passed to `createQuery` is built by string concatenation, the same
// `.executeUpdate()` chain shape is no longer parameterised — the
// receiver-chain walk sees a `binary_expression` at arg 0 of
// `createQuery`, not a `string_literal`, and refuses to synthesise the
// reflexive `Sanitizer(SQL_QUERY)`.  The structural sink stays in place
// and a finding is expected.
public class SqliJpaCreateQueryConcat {
    private final EntityManager em;

    public SqliJpaCreateQueryConcat(EntityManager em) {
        this.em = em;
    }

    public void clearByName(String name) {
        em.createQuery("delete from EventEntity where name = '" + name + "'").executeUpdate();
    }
}
