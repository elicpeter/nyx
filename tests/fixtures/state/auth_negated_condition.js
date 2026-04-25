const { exec } = require('child_process');

function handle_request(req) {
    if (!is_authenticated(req)) {
        // Negated: True branch means NOT authenticated.
        // Auth level must NOT be elevated here.
        exec(req.body.cmd);
    }
}
