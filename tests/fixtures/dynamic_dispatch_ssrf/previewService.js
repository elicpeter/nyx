const http = require("http");
const https = require("https");

function fetchUrl(targetUrl) {
    const lib = targetUrl.startsWith("https") ? https : http;
    const req = lib.request(targetUrl);
    return req;
}

module.exports = { fetchUrl };
