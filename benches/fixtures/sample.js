const { execSync } = require("child_process");

function getUserInput() {
  return process.env.USER_INPUT || "";
}

function sanitizeHtml(input) {
  return input.replace(/[<>&"']/g, "");
}

function renderPage(data) {
  document.innerHTML = data;
}

function safeRender() {
  const input = getUserInput();
  const clean = sanitizeHtml(input);
  renderPage(clean);
}

function unsafeRender() {
  const input = getUserInput();
  renderPage(input);
}

function runShell(cmd) {
  execSync(cmd);
}

function unsafeExec() {
  const input = getUserInput();
  runShell(input);
}

module.exports = { safeRender, unsafeRender, unsafeExec };
