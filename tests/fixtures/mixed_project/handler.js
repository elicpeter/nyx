var child_process = require("child_process");
var fs = require("fs");

// Infrastructure provisioning tool — JavaScript CLI frontend.
// Handles user commands and delegates to backend services.

// ───── CLI command handler ─────

// Executes a user-specified infrastructure command.
// VULN: process.env flows into child_process.exec
function executeInfraCommand() {
    var provider = process.env.CLOUD_PROVIDER;
    var action = process.env.INFRA_ACTION;
    var cmd = provider + "-cli " + action;
    child_process.exec(cmd, function(err, stdout, stderr) {
        if (err) {
            console.error("Infrastructure command failed:", stderr);
            return;
        }
        console.log("Result:", stdout);
    });
}

// ───── Template rendering ─────

// Renders infrastructure status into the dashboard.
// VULN: process.env flows into eval (code injection)
function renderStatusWidget() {
    var templateCode = process.env.STATUS_WIDGET_TEMPLATE;
    var widget = eval(templateCode);
    document.getElementById("status").innerHTML = widget;
}

// ───── Provisioning log viewer ─────

// Reads provisioning logs and renders them.
// VULN: process.env → child_process.execSync (command injection)
function fetchProvisioningLogs() {
    var logDir = process.env.PROVISIONING_LOG_DIR;
    var output = child_process.execSync("cat " + logDir + "/latest.log");
    document.getElementById("logs").innerHTML = output.toString();
}

// ───── SSH key management ─────

// Generates an SSH key pair using a command from env.
// VULN: process.env flows into child_process.spawn
function generateSSHKey() {
    var keygenPath = process.env.KEYGEN_BINARY;
    var proc = child_process.spawn(keygenPath, ["-t", "ed25519", "-f", "/tmp/id_deploy"]);
    proc.on("close", function(code) {
        console.log("Key generation exited with code", code);
    });
}

// ───── Safe utility ─────

// SAFE: hardcoded command, no taint flow
function checkKubectlVersion() {
    var output = child_process.execSync("kubectl version --client --short");
    console.log("kubectl:", output.toString());
}
