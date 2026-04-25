const { exec } = require('child_process');

function handle_request(req) {
    requireRole(req, 'admin');
    exec(req.body.cmd);
}
