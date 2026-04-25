const { execSync } = require('child_process');

function dispatch(cmdParam, urlParam) {
    execSync(cmdParam);      // param 0 -> SHELL_ESCAPE sink
    fetch(urlParam);         // param 1 -> SSRF sink
}

module.exports = { dispatch };
