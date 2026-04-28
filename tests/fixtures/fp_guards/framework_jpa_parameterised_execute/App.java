// FP GUARD — framework-safe pattern (JPA parameterised execute).
//
// The terminal `.executeUpdate()` / `.executeQuery()` on a
// `javax.persistence.Query` is zero-arg — the SQL was bound upstream
// from a string literal via `entityManager.createQuery(LITERAL)` /
// `createNativeQuery(LITERAL)`, and any per-call values arrive
// through `.setParameter(...)` (which the JPA driver escapes).  The
// engine walks the receiver chain to find the SQL-bind call, verifies
// arg 0 is a `string_literal`, and synthesises a same-node
// `Sanitizer(SQL_QUERY)` so the reflexive dominance suppresses both
// `cfg-unguarded-sink` and `taint-unsanitised-flow` for these chains.
//
// Distilled from keycloak `JpaEventStoreProvider.java` (~150 cluster
// of identical-shape findings on the 2026-04-28 baseline).
//
// Expected: NO `cfg-unguarded-sink` or `taint-unsanitised-flow` findings.
import javax.persistence.EntityManager;
import javax.servlet.http.HttpServletRequest;

public class App {
    private final EntityManager em;

    public App(EntityManager em) {
        this.em = em;
    }

    public void clearAll() {
        em.createQuery("delete from EventEntity").executeUpdate();
    }

    public void clearOlder(HttpServletRequest req) {
        long olderThan = Long.parseLong(req.getParameter("olderThan"));
        em.createQuery("delete from EventEntity where time < :time")
          .setParameter("time", olderThan)
          .executeUpdate();
    }

    public void clearByRealm(HttpServletRequest req) {
        String realmId = req.getParameter("realmId");
        em.createNativeQuery("delete from event_entity where realm_id = ?")
          .setParameter(1, realmId)
          .executeUpdate();
    }
}
