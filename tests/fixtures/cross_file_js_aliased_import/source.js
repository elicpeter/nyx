/**
 * SOURCE module — exports a function that reads a user-controlled environment
 * variable.  The export name will be renamed (aliased) at the import site in
 * app.js to test that Nyx resolves renamed bindings correctly.
 */
function getInput() {
    return process.env.USER_CMD; // taint source
}

module.exports = { getInput };
