// cal.com / NextAuth idiom: destructure `user` from a session
// container, then use `user.id` (or a downstream copy) as a SQL
// parameter.  The destructured local IS the authenticated actor —
// its `.id` is the caller's own id, not a foreign tenant id.
//
// Real-repo cluster: ~tens of cal.com handlers in
// `apps/web/.../*/route.ts` shaped like this.
//
// Engine fix: extend `collect_self_actor_binding` (and the
// `variable_declarator` dispatch arm wired in 2026-04-27 morning)
// to handle `object_pattern` patterns when the RHS is a
// session-container chain (`ctx.session`, `req.session`, etc.) or a
// known session-getter call (`getServerSession`).  The destructured
// `user` becomes a `self_actor_var`; downstream `user.id` /
// `user.email` accesses then count as actor context, suppressing the
// ownership-gap finding.

import { db } from "../db";

type Ctx = {
  session: { user: { id: string; email: string } };
};

// Destructure `user` from `ctx.session` — `user` is the actor.
export async function getMine(ctx: Ctx) {
  const { user } = ctx.session;
  return await db.findById(user.id);
}

// `user.email` access on the destructured local is also actor context.
export async function emailMine(ctx: Ctx) {
  const { user } = ctx.session;
  return await db.findByEmail(user.email);
}

// Destructure with rename: `{ user: me }` — `me.id` is still actor
// context because `me` was bound from the session container.
export async function getMineRenamed(ctx: Ctx) {
  const { user: me } = ctx.session;
  return await db.findById(me.id);
}

// `getServerSession()` call form (NextAuth idiom).
declare function getServerSession(): Promise<{ user: { id: string } }>;

export async function getMineFromServerSession() {
  const { user } = await getServerSession();
  return await db.findById(user.id);
}

// `const { id } = req.user;` — RHS is the canonical authed-user base
// (`is_self_scoped_session_base_text`); the destructured `id` is the
// actor's own id.
type Req = { user: { id: string } };
export async function getMineFromReqUser(req: Req) {
  const { id } = req.user;
  return await db.findById(id);
}
