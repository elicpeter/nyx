/**
 * SOURCE module — exports a function that passes its parameter through to
 * the return value.  The export name will be renamed (aliased) at the import
 * site in app.js to test that Nyx resolves renamed bindings correctly.
 */
function getInput(data) {
    return data; // passthrough: param 0 → return
}

module.exports = { getInput };
