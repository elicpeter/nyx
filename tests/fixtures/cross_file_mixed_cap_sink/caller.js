const { dispatch } = require('./dispatch');

function handleRequest() {
    const input = process.env.USER_INPUT;

    // Case 1: tainted -> param 0 (CMD sink), should produce CMD finding
    dispatch(input, "https://safe.example.com");

    // Case 2: tainted -> param 1 (SSRF sink), should produce SSRF finding
    dispatch("echo hello", input);
}
