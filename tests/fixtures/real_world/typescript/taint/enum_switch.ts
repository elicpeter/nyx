import child_process from 'child_process';

enum Action {
    Run = 'run',
    Stop = 'stop',
}

function handleAction(action: Action, payload: string): void {
    switch (action) {
        case Action.Run:
            child_process.exec(payload);
            break;
        case Action.Stop:
            console.log('stopping');
            break;
    }
}
