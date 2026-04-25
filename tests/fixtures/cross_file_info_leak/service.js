/**
 * Returns debug information including sensitive environment variables.
 * process.env is a source (Cap::all()), so the return value carries
 * source-independent taint via SsaFuncSummary.source_caps.
 */
function getDebugInfo(req) {
    const dbUrl = process.env.DATABASE_URL;
    const secret = process.env.SESSION_SECRET;
    return {
        session: req.session,
        dbUrl: dbUrl,
        secret: secret
    };
}

module.exports = { getDebugInfo };
