import * as fs from 'fs';

function readConfigUnsafe(path: string): string {
    var content = fs.readFileSync(path, 'utf8');
    var config = JSON.parse(content);
    if (config.error) {
        console.log('Error in config');
        // falls through without returning!
    }
    return config.value;
}

function readConfigSafe(path: string): string {
    var content = fs.readFileSync(path, 'utf8');
    var config = JSON.parse(content);
    if (config.error) {
        throw new Error('Invalid config: ' + config.error);
    }
    return config.value;
}
