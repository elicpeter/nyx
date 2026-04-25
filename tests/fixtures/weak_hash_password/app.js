const md5 = require("md5");
const crypto = require("crypto");

function hashPassword(password) {
    // VULN: md5 is not suitable for password hashing
    return md5(password);
}

function hashToken(token) {
    // VULN: sha1 via crypto.createHash is weak
    return crypto.createHash("sha1").update(token).digest("hex");
}
