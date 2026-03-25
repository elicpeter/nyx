const { getUserInput, sanitize } = require('./utils');

// Tainted: source flows directly to eval without sanitization
const raw = getUserInput();
eval(raw);
