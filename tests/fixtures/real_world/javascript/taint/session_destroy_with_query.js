var express = require('express');
var router = express.Router();

router.post('/logout', function(req, res) {
    var returnTo = req.query.next;
    req.session.destroy(function() {
        res.redirect("/login");
    });
});
