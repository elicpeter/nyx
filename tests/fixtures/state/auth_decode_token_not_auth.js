const { exec } = require('child_process');

function handle_request(req) {
    // decodeToken() parses but does not enforce auth — should still fire
    var payload = decodeToken(req.headers.authorization);
    exec(req.body.cmd);
}
