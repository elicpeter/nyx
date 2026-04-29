// Vulnerable counterpart to `safe_trpc_ctx_user_options.ts`: same
// TRPC shape, but the SQL parameter is `input.id` (a foreign id from
// the request body), not `ctx.user.id`.  The TRPC ctx-typed
// self-actor recognition must NOT also exempt `input.<scoped_id>`
// targets — that would mask real IDOR bugs.

type TrpcSessionUser = { id: string; email: string };

type DeleteOptions = {
  ctx: {
    user: NonNullable<TrpcSessionUser>;
  };
  input: { targetUserId: string };
};

declare const db: {
  deleteUser: (userId: string) => Promise<unknown>;
};

export const deleteHandler = async ({ ctx, input }: DeleteOptions) => {
  // `input.targetUserId` is a request-body field, NOT the actor's
  // own id.  The TRPC ctx fix only marks `ctx.user.<id-like>` as
  // actor context; `input.<X>` keeps flagging.
  const _ = ctx;
  return await db.deleteUser(input.targetUserId);
};
