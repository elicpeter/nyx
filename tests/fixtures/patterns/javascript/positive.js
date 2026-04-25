// Positive fixture: each snippet should trigger the named pattern.

// js.code_exec.eval
function triggerEval(code) {
    eval(code);
}

// js.code_exec.new_function
function triggerNewFunction(body) {
    var fn = new Function(body);
}

// js.code_exec.settimeout_string
function triggerSetTimeout() {
    setTimeout("alert(1)", 1000);
}

// js.xss.document_write
function triggerDocumentWrite(data) {
    document.write(data);
}

// js.xss.outer_html
function triggerOuterHtml(el, data) {
    el.outerHTML = data;
}

// js.xss.insert_adjacent_html
function triggerInsertAdjacentHtml(el, data) {
    el.insertAdjacentHTML("beforeend", data);
}

// js.prototype.proto_assignment
function triggerProtoAssignment(obj) {
    obj.__proto__ = { malicious: true };
}

// js.xss.location_assign
function triggerLocationAssign(url) {
    window.location = url;
}

// js.xss.cookie_write
function triggerCookieWrite(sid) {
    document.cookie = "session=" + sid;
}

// js.secrets.hardcoded_secret
var config = { secret: "keyboard-cat-fallback", password: "admin123" };

// js.crypto.weak_hash
function triggerWeakHash() {
    var hash = crypto.createHash("md5");
}

// js.crypto.weak_hash_import
function triggerWeakHashImport(password) {
    var hash = md5(password);
}

// js.crypto.math_random
function triggerMathRandom() {
    var token = Math.random();
}

// js.config.reject_unauthorized
var opts = { rejectUnauthorized: false, timeout: 3000 };

// js.secrets.fallback_secret
var sessionSecret = process.env.SESSION_SECRET || "fake-default-session-secret";

// js.config.verbose_error_response
function errorHandler(err, req, res) {
    var error = err;
    res.status(500).render("errors/error", { title: "Server Error", error });
}

// js.config.cors_dynamic_origin
function setCors(req, res) {
    res.setHeader("Access-Control-Allow-Origin", origin);
}
