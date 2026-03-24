const { exec } = require('child_process');

function handle_request(req) {
    if (is_authenticated(req)) {
        exec(req.body.cmd);
    }
}
