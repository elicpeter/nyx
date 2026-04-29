// Express handler shape: `req.user.id` is the authenticated user
// (passport / express-session). The local `userId` copy of
// `req.user.id` is a self-actor-id and must not trigger the rule.
async function getApiKeysFromUserId(_userId) {
  return [];
}

async function handler(req, _res) {
  const userId = req.user.id;
  const apiKeys = await getApiKeysFromUserId(userId);
  return apiKeys;
}

module.exports = { handler };
