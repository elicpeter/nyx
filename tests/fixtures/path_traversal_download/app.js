function downloadFile(req, res) {
    var userPath = req.query.path;
    // VULN: user-controlled path flows into res.download (path traversal)
    res.download(userPath);
}
