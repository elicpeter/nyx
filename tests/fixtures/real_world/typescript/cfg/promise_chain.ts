import child_process from 'child_process';
import { promisify } from 'util';

var execAsync = promisify(child_process.exec);

async function pipeline(input: string): Promise<string> {
    var step1 = await execAsync('echo ' + input);
    var step2 = await execAsync('wc -c <<< "' + step1.stdout + '"');
    return step2.stdout;
}

async function safePipeline(input: string): Promise<string> {
    var sanitized = input.replace(/[^a-zA-Z0-9]/g, '');
    var step1 = await execAsync('echo ' + sanitized);
    return step1.stdout;
}
