var child_process = require('child_process');

child_process.exec('echo hello', function(err, stdout) {
    console.log(stdout);
});
