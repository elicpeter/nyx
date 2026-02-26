var child_process = require('child_process');

function handleAction(action, userInput) {
    switch (action) {
        case 'eval':
            eval(userInput);
            break;
        case 'log':
            console.log(userInput);
            break;
        case 'exec':
            child_process.execSync(userInput);
        case 'safe':
            console.log('safe action');
            break;
        default:
            break;
    }
}
