/**
 * Search service — interpolates user input into raw SQL.
 * The cross-file summary should show param 0 → SQL_QUERY sink.
 */
async function globalSearch(term) {
    const sql = "SELECT * FROM items WHERE name LIKE '%" + term + "%'";
    const result = await db.query(sql);
    return result.rows;
}

module.exports = { globalSearch };
