"use strict";

// Distilled from outline `server/migrations/*.js`.  A Sequelize migration runs
// constant DDL through `sequelize.query(sql, options)`.  The SQL template
// (arg 0) is a compile-time constant; the trailing options / bind argument
// (arg 1) is a non-constant object or identifier that is NOT an injection
// vector.  The raw-SQL sinks are gated with `payload_args = [0]`, so
// `cfg-unguarded-sink` must NOT fire on any of these, and with no source
// `taint-unsanitised-flow` must stay silent.
module.exports = {
  async up(queryInterface, Sequelize) {
    const options = { type: "RAW", logging: false };

    // Constant SQL, non-constant options identifier (defeats the whole-call
    // const check; only arg 0 is the injection vector).
    await queryInterface.sequelize.query(
      `ALTER INDEX "collection_groups_group_id" RENAME TO "group_permissions_group_id"`,
      options
    );

    // Constant SQL with a literal options object.
    await queryInterface.sequelize.query(
      `ALTER TABLE ONLY collection_groups RENAME CONSTRAINT "cg_fkey" TO "gp_fkey"`,
      { raw: true }
    );

    // Constant SQL, no options.
    await queryInterface.sequelize.query(`CREATE INDEX idx_foo ON foo (bar)`);
  },

  async down(queryInterface) {
    await queryInterface.sequelize.query(`DROP INDEX idx_foo`);
  },
};
