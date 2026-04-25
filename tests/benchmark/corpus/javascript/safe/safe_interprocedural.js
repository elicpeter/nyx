const express = require('express');
const DOMPurify = require('dompurify');
const app = express();
function clean(s) {
    return DOMPurify.sanitize(s);
}
app.get('/greet', (req, res) => {
    const name = req.query.name;
    document.getElementById('output').innerHTML = clean(name);
});
