const { exec } = require('child_process');

function handle_request(req) {
    if (jwt.verify(req.token)) {
        exec(req.body.cmd);
    }
}
