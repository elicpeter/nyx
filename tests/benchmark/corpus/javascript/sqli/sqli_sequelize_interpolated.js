"use strict";

// Recall counterpart to `safe/safe_sequelize_migration_const_sql.js`.  The raw
// SQL sinks are gated with `payload_args = [0]` (only the SQL string is the
// injection vector, not the bind/options argument), so a constant SQL template
// with a non-constant options object is suppressed — but attacker-controlled
// data interpolated INTO the SQL string (arg 0) must still fire
// `taint-unsanitised-flow`.
async function handler(req, res) {
  const name = req.query.name;
  await sequelize.query(
    `SELECT * FROM users WHERE name = '${name}'`,
    { type: "SELECT" }
  );
}

module.exports = { handler };
