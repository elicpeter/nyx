"use strict";

// Distilled from outline `server/migrations/*.js`.  A Sequelize migration runs
// constant DDL through `sequelize.query(sql, { transaction })` wrapped in a
// `sequelize.transaction(async (transaction) => { … })` callback.  The
// `first_member_label` CFG helper hoists the inner `sequelize.query` SQL_QUERY
// Sink label onto the OUTER `.transaction` wrapper node — whose own argument is
// the callback, not the SQL.  The inner SQL template (payload arg 0) is a
// compile-time constant, so `cfg-unguarded-sink` must NOT fire on the
// `.transaction` node (nor the inner `.query` node), and with no source
// `taint-unsanitised-flow` must stay silent.
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.sequelize.query(
        `DROP VIEW IF EXISTS collection_groups_view`,
        { transaction }
      );

      await queryInterface.sequelize.query(
        `ALTER TABLE ONLY collection_groups RENAME CONSTRAINT "cg_fkey" TO "gp_fkey"`,
        { transaction }
      );
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.sequelize.query(`DROP INDEX idx_foo`, { transaction });
    });
  },
};
