// TRPC handler typed-extractor self-actor recognition (real-repo
// precision, 2026-04-27 JS slice 2).  Pinned in
// `auth_analysis_tests::trpc_ctx_user_options_does_not_flag`.

type TrpcSessionUser = { id: string; email: string };

type GetOptions = {
  ctx: {
    user: NonNullable<TrpcSessionUser>;
  };
  input: { id: string };
};

declare const db: {
  findOwn: (userId: string) => Promise<unknown>;
};

export const getMine = async ({ ctx, input }: GetOptions) => {
  const _ = input;
  return await db.findOwn(ctx.user.id);
};

// Chained destructure: `const { user } = ctx;` after TRPC param.
// The dynamic self_scoped_session_bases lookup lifts the local
// `user` to a self-actor binding.
export const getMineChained = async ({ ctx }: GetOptions) => {
  const { user } = ctx;
  return await db.findOwn(user.id);
};
