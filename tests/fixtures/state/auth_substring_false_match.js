const { exec } = require('child_process');

function handle_request(req) {
    if (not_is_authenticated_cache(req)) {
        // "not_is_authenticated_cache" must NOT match "is_authenticated".
        // Without a real auth check, the finding should still fire.
        exec(req.body.cmd);
    }
}
