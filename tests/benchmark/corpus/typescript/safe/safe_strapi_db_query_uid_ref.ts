// Strapi-style ORM accessor chain `<obj>.db.query(UID).<orm_method>(...)`
// where the model UID arrives by *reference* rather than as an inline string
// literal — the dominant shape in real Strapi code:
//   * variable parameter        (`db.query(uid).findOne(...)`)
//   * module-constant identifier (`db.query(RELEASE_MODEL_UID).findMany(...)`)
//   * member access             (`db.query(models.article).count(...)`)
//
// A model UID is never runtime-computed SQL, and the trailing ORM method
// (findOne / findMany / update / delete / count / …) proves the chain is
// parameterised: a raw driver's `query(sql)` returns a Promise that cannot
// chain those methods.  None of these should fire as a SQL-injection sink
// (`cfg-unguarded-sink` / `taint-unsanitised-flow`).  Distilled from strapi
// `packages/core/core/src/services/document-service/repository.ts:331` and
// `packages/core/content-releases/server/src/services/release.ts`.

declare const strapi: any;

const RELEASE_MODEL_UID = 'plugin::content-releases.release';
const models = { article: 'api::article.article' };

// variable-parameter model UID
async function findByDocumentId(uid: string, documentId: string) {
    return strapi.db.query(uid).findOne({
        select: ['id', 'name'],
        where: { documentId },
    });
}

// module-constant identifier model UID
async function listReleases(name: string) {
    return strapi.db.query(RELEASE_MODEL_UID).findMany({
        where: { name },
    });
}

// member-access model UID
async function countArticles(name: string) {
    return strapi.db.query(models.article).count({ where: { name } });
}

// variable UID with update / delete accessors
async function updateRelease(uid: string, id: number, data: unknown) {
    await strapi.db.query(uid).update({ where: { id }, data });
    return strapi.db.query(uid).delete({ where: { id } });
}

// `(await ...)` wrapper + const assignment (migrations/index.ts:60 shape)
const RELEASE_MODEL_UID2 = 'plugin::content-releases.release';
async function awaitWrapped(status: null) {
    const rel = (await strapi.db.query(RELEASE_MODEL_UID2).findMany({ where: { status } }));
    return rel;
}

// `(await ...) > 0` binary wrapper (admin/server user.ts:199 shape)
async function existsCount(attrs: unknown): Promise<boolean> {
    return (await strapi.db.query('admin::user').count({ where: attrs })) > 0;
}

// `.load` relation accessor + `as` return cast (document-service components.ts shape)
async function loadComponents(uid: string, entity: unknown) {
    return strapi.db.query(uid).load(entity, {}) as Promise<unknown>;
}

// ORM call nested inside a `Promise.all([...])` array argument
// (content-manager single-types.ts:49 shape)
async function inPromiseAll(model: string) {
    return Promise.all([strapi.db.query(model).findOne({ select: ['documentId'] })]);
}

// `key as UID.Schema` type-cast UID argument (entity-validator index.ts:572 shape)
async function castUid(key: string) {
    return strapi.db.query(key as any).count({ where: {} });
}
