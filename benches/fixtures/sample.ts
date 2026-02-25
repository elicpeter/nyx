import { execSync } from "child_process";

function getUserInput(): string {
  return process.env.USER_INPUT || "";
}

function sanitizeHtml(input: string): string {
  return input.replace(/[<>&"']/g, "");
}

function renderPage(data: string): void {
  document.body.innerHTML = data;
}

function runCommand(cmd: string): void {
  execSync(cmd);
}

function safeRender(): void {
  const input = getUserInput();
  const clean = sanitizeHtml(input);
  renderPage(clean);
}

function unsafeExec(): void {
  const input = getUserInput();
  runCommand(input);
}

export { safeRender, unsafeExec };
