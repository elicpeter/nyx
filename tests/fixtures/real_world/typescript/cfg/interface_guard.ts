import child_process from 'child_process';

interface UserInput {
    command: string;
    isAdmin: boolean;
}

function runIfAdmin(input: UserInput): void {
    if (!input.isAdmin) {
        return;
    }
    child_process.exec(input.command);
}

function runUnchecked(input: UserInput): void {
    child_process.exec(input.command);
}
