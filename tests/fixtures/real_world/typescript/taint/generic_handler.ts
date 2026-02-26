import child_process from 'child_process';

function executeCommand<T extends { cmd: string }>(input: T): void {
    child_process.exec(input.cmd);
}

function processUserInput(userInput: string): void {
    executeCommand({ cmd: userInput });
}
