var child_process = require("child_process");
var crypto = require("crypto");
var fs = require("fs");

// ───── User authentication route ─────

// POST /auth/login
// Reads credentials from request body, constructs a shell command to
// check credentials via an external LDAP tool.
// VULN: req.body flows into child_process.exec
function handleLogin(req, res) {
    var username = req.body.username;
    var password = req.body.password;

    var cmd = "ldapwhoami -x -D 'cn=" + username + ",dc=corp' -w '" + password + "'";
    child_process.exec(cmd, function(err, stdout, stderr) {
        if (err) {
            res.status(401).send("Authentication failed");
            return;
        }
        var token = crypto.randomBytes(32).toString("hex");
        res.json({ token: token, user: username });
    });
}

// ───── Search endpoint ─────

// GET /api/search
// User-supplied query parameter is passed directly to eval for "dynamic filtering".
// VULN: req.query flows into eval (code injection)
function handleSearch(req, res) {
    var query = req.query.q;
    var filterExpr = req.query.filter;

    // Developer thought this was clever for dynamic filtering
    var filterFn = eval("(function(item) { return " + filterExpr + "; })");

    var results = getDatabase().filter(filterFn);
    res.json({ results: results, query: query });
}

// ───── Admin panel rendering ─────

// GET /admin/dashboard
// Renders an admin dashboard; user-supplied name goes into innerHTML.
// VULN: req.query flows into innerHTML (XSS)
function renderDashboard(req, res) {
    var userName = req.query.name;
    var greeting = "<h1>Welcome, " + userName + "</h1>";
    document.getElementById("header").innerHTML = greeting;

    var statsHtml = req.query.stats;
    document.getElementById("stats-panel").innerHTML = statsHtml;
}

// ───── Webhook handler ─────

// POST /webhooks/deploy
// Reads a deployment command from process.env, executes it.
// VULN: process.env flows into child_process.execSync
function handleDeployWebhook(req, res) {
    var secret = req.headers["x-webhook-secret"];
    if (secret !== process.env.WEBHOOK_SECRET) {
        res.status(403).send("Forbidden");
        return;
    }

    var deployCmd = process.env.DEPLOY_COMMAND;
    var output = child_process.execSync(deployCmd);
    res.send("Deployed: " + output.toString());
}

// ───── File preview ─────

// GET /files/preview
// Reads a file based on user-supplied path, writes content to page.
// VULN: req.query flows into innerHTML (reflected XSS via file content)
function previewFile(req, res) {
    var filePath = req.query.path;
    var content = fs.readFileSync(filePath, "utf-8");
    document.getElementById("preview").innerHTML = content;
}

// ───── Cookie-based session ─────

// POST /session/set
// Sets a cookie from request parameters.
// VULN: document.cookie write from user input
function setSessionCookie(req, res) {
    var sessionId = req.params.sid;
    document.cookie = "session=" + sessionId + "; path=/; HttpOnly";
}

// ───── Prototype pollution ─────

// POST /api/config/merge
// Merges user-supplied config into the global config object.
// VULN: prototype pollution via __proto__
function mergeConfig(req, res) {
    var userConfig = JSON.parse(req.body.config);
    for (var key in userConfig) {
        if (key === "__proto__") {
            // Developer forgot to skip this
            Object.prototype[key] = userConfig[key];
        }
        globalConfig[key] = userConfig[key];
    }
    res.json({ status: "ok" });
}

// ───── Timer-based polling ─────

// Sets up a polling interval with a string argument.
// VULN: setTimeout with string is equivalent to eval
function startPolling() {
    var interval = 5000;
    setTimeout("checkForUpdates()", interval);
    setInterval("refreshDashboard()", 30000);
}

// ───── Safe patterns ─────

// GET /api/profile
// SAFE: user input sanitized with DOMPurify before rendering
function renderProfile(req, res) {
    var bio = req.query.bio;
    var cleanBio = DOMPurify.sanitize(bio);
    document.getElementById("bio").innerHTML = cleanBio;
}

// GET /api/redirect
// SAFE: URL properly encoded before use
function safeRedirect(req, res) {
    var target = req.query.url;
    var encoded = encodeURIComponent(target);
    res.redirect("/go?url=" + encoded);
}
