const { exec } = require('child_process');

function handle_request(req) {
    // generateToken() is NOT an auth check — should still fire
    var token = generateToken(req.user);
    exec(req.body.cmd);
}
