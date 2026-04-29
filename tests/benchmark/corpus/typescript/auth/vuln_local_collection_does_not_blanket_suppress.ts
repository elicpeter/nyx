// Vulnerable counterpart to `safe_local_collection_receiver.ts`.
//
// Pinned to prove the LocalCollection-receiver fix does NOT
// blanket-suppress missing-ownership findings on real DB / API
// receivers that happen to share method names (`get`, `find`, `set`)
// with JS built-in collections.  When the receiver type is a real
// `Prisma` / `Repository` / `db` chain — not a tracked Map / Set /
// Array — the auth analyser must still fire.

interface PrismaClient {
  user: {
    findUnique(args: { where: { id: string } }): Promise<{ id: string } | null>;
    update(args: { where: { id: string }; data: object }): Promise<void>;
  };
}

declare const prisma: PrismaClient;

// User passes an attacker-controlled id.  No prior auth check; receiver
// is a Prisma client (NOT a Map / Set / Array), so the missing-ownership
// rule must fire on `prisma.user.findUnique`.
export async function dangerousFetch(targetUserId: string) {
  return prisma.user.findUnique({ where: { id: targetUserId } });
}

export async function dangerousMutate(targetUserId: string, data: object) {
  return prisma.user.update({ where: { id: targetUserId }, data });
}
