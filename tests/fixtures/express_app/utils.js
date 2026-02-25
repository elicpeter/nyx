var child_process = require("child_process");
var crypto = require("crypto");
var fs = require("fs");

// ───── Background job runner ─────

// Runs a job command read from environment.
// VULN: process.env flows into child_process.exec
function runScheduledJob() {
    var jobCmd = process.env.CRON_JOB_CMD;
    child_process.exec(jobCmd, function(err, stdout, stderr) {
        if (err) {
            console.error("Job failed:", stderr);
            return;
        }
        console.log("Job output:", stdout);
    });
}

// Spawns a worker process from environment config.
// VULN: process.env flows into child_process.spawn
function spawnWorker() {
    var workerBin = process.env.WORKER_BINARY;
    var workerArgs = process.env.WORKER_ARGS.split(" ");
    var proc = child_process.spawn(workerBin, workerArgs);
    proc.stdout.on("data", function(data) {
        console.log("Worker: " + data);
    });
}

// ───── Template rendering helper ─────

// Renders user-visible content by injecting location data.
// VULN: window.location flows into innerHTML
function renderBreadcrumb() {
    var currentPath = document.location.pathname;
    var parts = currentPath.split("/");
    var html = parts.map(function(p) {
        return "<a href='/" + p + "'>" + p + "</a>";
    }).join(" &gt; ");
    document.getElementById("breadcrumb").innerHTML = html;
}

// ───── URL redirect handler ─────

// VULN: location.href assignment from user-controlled data
function handleExternalRedirect() {
    var target = window.location.hash.substring(1);
    window.location.href = target;
}

// ───── Markdown rendering ─────

// Uses document.write to render parsed markdown.
// VULN: document.write with dynamic content
function renderMarkdown(markdownHtml) {
    document.write("<div class='markdown'>" + markdownHtml + "</div>");
}

// ───── Insecure hashing ─────

// Uses MD5 for password hashing.
// VULN: weak hash algorithm
function hashPassword(password) {
    return crypto.createHash("md5").update(password).digest("hex");
}

// ───── Dynamic regex from user input ─────

// VULN: RegExp with user-controlled pattern (ReDoS risk)
function searchLogs(pattern) {
    var re = new RegExp(pattern, "gi");
    return logs.filter(function(line) { return re.test(line); });
}

// ───── Safe utility ─────

// SAFE: no taint flows, pure computation
function calculateChecksum(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}
