// Destructured `{ user }` from a session container — pinned in
// `auth_analysis_tests::destructured_session_user_does_not_flag`.

type Ctx = {
  session: { user: { id: string } };
};

declare const db: { findOwn: (id: string) => Promise<unknown> };

export async function handler(ctx: Ctx) {
  const { user } = ctx.session;
  return await db.findOwn(user.id);
}
