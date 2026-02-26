import * as fs from 'fs';

function processFiles(paths: string[]): void {
    var handles: number[] = [];
    for (var i = 0; i < paths.length; i++) {
        handles.push(fs.openSync(paths[i], 'r'));
    }
    // Process all
    for (var j = 0; j < handles.length; j++) {
        var buf = Buffer.alloc(1024);
        fs.readSync(handles[j], buf);
    }
    // Forgot to close any handles!
}

function processFilesSafe(paths: string[]): void {
    var handles: number[] = [];
    for (var i = 0; i < paths.length; i++) {
        handles.push(fs.openSync(paths[i], 'r'));
    }
    for (var j = 0; j < handles.length; j++) {
        var buf = Buffer.alloc(1024);
        fs.readSync(handles[j], buf);
    }
    for (var k = 0; k < handles.length; k++) {
        fs.closeSync(handles[k]);
    }
}
