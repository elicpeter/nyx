"use strict";

// Recall counterpart to `safe/safe_sequelize_transaction_const_sql.js`: the same
// `sequelize.transaction(async (transaction) => { sequelize.query(…, { transaction }) })`
// wrapper, but the inner SQL is interpolated from user input.  The hoisted-sink
// provenance records the inner `sequelize.query` payload arg 0 as NON-constant
// (a template with `${…}` interpolation), so the syntactic payload-const
// suppression must NOT fire and `taint-unsanitised-flow` must still report the
// flow from `req.query.name` into the inner query.
const express = require("express");
const app = express();

app.get("/users", async (req, res) => {
  const name = req.query.name;
  await sequelize.transaction(async (transaction) => {
    await sequelize.query(
      `SELECT * FROM users WHERE name = '${name}'`,
      { transaction }
    );
  });
  res.end();
});
