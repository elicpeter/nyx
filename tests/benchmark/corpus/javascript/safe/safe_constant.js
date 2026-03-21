const { exec } = require('child_process');
function checkHealth() {
    exec("echo health-ok");
}
checkHealth();
