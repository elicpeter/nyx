var child_process = require('child_process');
var util = require('util');
var execAsync = util.promisify(child_process.exec);

async function runCommand(userCmd) {
    try {
        var result = await execAsync(userCmd);
        return result.stdout;
    } catch (err) {
        return err.message;
    }
}

async function fetchAndExec(url) {
    var response = await fetch(url);
    var data = await response.json();
    child_process.exec(data.command, function(err, stdout) {
        return stdout;
    });
}
