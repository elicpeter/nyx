const { globalSearch } = require('./search');

/**
 * VULN: req.query.q (user input) flows through globalSearch() — a
 * cross-file function that concatenates its param into raw SQL and
 * passes it to db.query() (SQL_QUERY sink).
 */
function handleSearch(req, res) {
    const term = req.query.q;
    const results = globalSearch(term);
    res.json(results);
}
