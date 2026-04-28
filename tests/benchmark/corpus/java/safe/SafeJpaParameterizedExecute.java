import javax.persistence.EntityManager;
import java.util.List;

// Distilled from keycloak's
// `model/jpa/src/main/java/org/keycloak/events/jpa/JpaEventStoreProvider.java`:
// `em.createQuery(LITERAL).executeUpdate()` and the bind-parameter chain
// `em.createQuery(LITERAL).setParameter(...).executeUpdate()` are the
// canonical JPA parameterised-execute shapes.  The terminal zero-arg
// `executeUpdate` / `executeQuery` is not where SQL is built — the SQL
// was bound upstream from a string literal, and any per-call values
// arrive through `setParameter`, which the JPA driver escapes.  Engine
// must synthesise a same-node `Sanitizer(SQL_QUERY)` so neither
// `cfg-unguarded-sink` nor `taint-unsanitised-flow` fires.
public class SafeJpaParameterizedExecute {
    private final EntityManager em;

    public SafeJpaParameterizedExecute(EntityManager em) {
        this.em = em;
    }

    public void clearAll() {
        em.createQuery("delete from EventEntity").executeUpdate();
    }

    public void clearOlder(long olderThan) {
        em.createQuery("delete from EventEntity where time < :time")
          .setParameter("time", olderThan)
          .executeUpdate();
    }

    public List<?> listAll() {
        return em.createQuery("select e from EventEntity e").getResultList();
    }

    public void clearByRealm(String realmId) {
        em.createNativeQuery("delete from event_entity where realm_id = ?")
          .setParameter(1, realmId)
          .executeUpdate();
    }
}
