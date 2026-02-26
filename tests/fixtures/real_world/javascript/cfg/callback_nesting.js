var child_process = require('child_process');
var fs = require('fs');

function processInput(input, callback) {
    fs.readFile(input.path, 'utf8', function(err, data) {
        if (err) {
            return callback(err);
        }
        child_process.exec(data, function(execErr, stdout) {
            callback(execErr, stdout);
        });
    });
}
