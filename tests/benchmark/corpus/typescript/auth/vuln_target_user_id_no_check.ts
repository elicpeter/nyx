// Vulnerable counterpart to `safe_session_user_id_copy.ts`: the
// `userId` is bound from a route param (`req.params.targetUserId`,
// not from the session), so the rule must still flag the missing
// ownership check on the downstream prisma call.
async function deleteApiKeysFromUserId(_userId: number) {}

export const Handler = async (req: any, _res: any) => {
  const session = await getServerSession();
  if (!session) return;

  const userId = req.params.targetUserId;
  await deleteApiKeysFromUserId(userId);
};
