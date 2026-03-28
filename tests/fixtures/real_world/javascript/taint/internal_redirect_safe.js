var express = require('express');
var router = express.Router();

router.post('/projects/:id/archive', function(req, res) {
    var project = db.getProject(req.params.id);
    res.redirect(`/projects/${project.id}`);
});
