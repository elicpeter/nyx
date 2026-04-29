// cal.com TRPC handler shape — Options-typed parameter destructures
// `ctx` from a TRPC session-context whose `user` field holds the
// authenticated actor.
//
// Real-repo cluster: ~105 of cal.com's 768 remaining
// `js.auth.missing_ownership_check` findings are in
// `packages/trpc/server/routers/{viewer,loggedInViewer}/.../*.handler.ts`
// shaped like this.  `ctx.user.id` is the caller's own id, not a
// foreign tenant id.
//
// Engine fix (2026-04-27, JS slice 2): file-level pre-scan walks
// every `type_alias_declaration` / `interface_declaration` in the
// source-file root looking for a body that references a TRPC-marker
// type (`TrpcSessionUser`).  Each matched alias name (e.g.
// `GetOptions`, `UpdateOptions`) is added to the per-unit
// `trpc_alias_names`.  When a parameter is encountered whose type
// annotation references one of those aliases — or inlines
// `TrpcSessionUser` directly — the destructured `ctx` (with
// shorthand or rename) populates `self_scoped_session_bases` with
// `<localCtx>.user`.  `is_actor_context_subject` then treats
// `<localCtx>.user.<id-like>` subjects as actor context.
//
// Conservative: bare `ctx.user` is NOT added to the static
// session-base list.  Only TS handlers whose type annotation
// directly demonstrates a TRPC signature are exempted; non-TRPC
// `ctx` patterns continue to flag their cross-tenant lookups.

// Stand-in for `@calcom/trpc/server/types` — the real `TrpcSessionUser`
// import resolves to a NextAuth user struct.  Our scanner can't follow
// the import, so the marker is the LITERAL substring "TrpcSessionUser"
// in the alias body — which appears in cal.com's own type definitions.
type TrpcSessionUser = { id: string; email: string };

type GetOptions = {
  ctx: {
    user: NonNullable<TrpcSessionUser>;
  };
  input: { keyword: string };
};

type UpdateOptions = {
  ctx: {
    user: NonNullable<TrpcSessionUser>;
  };
};

declare const db: {
  getMyEvents: (userId: string) => Promise<unknown>;
  getMyEmails: (email: string) => Promise<unknown>;
  updateMine: (userId: string) => Promise<unknown>;
};

// Destructured shorthand: `{ ctx, input }`.  ctx.user.id is actor.
export const getHandler = async ({ ctx, input }: GetOptions) => {
  const _ = input;
  return await db.getMyEvents(ctx.user.id);
};

// `ctx.user.email` — same path, different field; still actor.
export const emailHandler = async ({ ctx }: GetOptions) => {
  return await db.getMyEmails(ctx.user.email);
};

// Destructured rename: `{ ctx: c }`.  c.user.id is actor.
export const renamedHandler = async ({ ctx: c }: UpdateOptions) => {
  return await db.updateMine(c.user.id);
};

// Plain identifier: `(opts: GetOptions)`.  opts.ctx.user.id is actor.
export const optsHandler = async (opts: GetOptions) => {
  return await db.getMyEvents(opts.ctx.user.id);
};

// Chained destructure (cal.com webhook handler shape).  The TRPC
// param-level pre-pass marks `ctx.user` as a session base; the
// downstream `const { user } = ctx;` then lifts the local `user` to
// self_actor_var via the dynamic self_scoped_session_bases lookup.
export const chainedDestructureHandler = async ({ ctx }: GetOptions) => {
  const { user } = ctx;
  return await db.getMyEvents(user.id);
};
