import child_process from 'child_process';

function Route(path: string) {
    return function(target: any, key: string, descriptor: PropertyDescriptor) {
        return descriptor;
    };
}

class Controller {
    handleExec(userInput: string) {
        child_process.exec(userInput);
    }

    handleEval(code: string) {
        eval(code);
    }
}
