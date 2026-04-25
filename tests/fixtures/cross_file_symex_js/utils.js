// Cross-file helper: source function in a utility module
function getUserInput() {
    return process.env.USER_INPUT;
}

function sanitize(val) {
    return val.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

module.exports = { getUserInput, sanitize };
