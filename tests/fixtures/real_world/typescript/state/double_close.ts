import * as fs from 'fs';

function doubleCloseRisk(path: string): void {
    var fd = fs.openSync(path, 'r');
    try {
        var buf = Buffer.alloc(1024);
        fs.readSync(fd, buf);
        fs.closeSync(fd);
    } catch (e) {
        fs.closeSync(fd); // might double-close if readSync succeeds then later code throws
    }
}

function safeClosePattern(path: string): void {
    var fd = fs.openSync(path, 'r');
    var closed = false;
    try {
        var buf = Buffer.alloc(1024);
        fs.readSync(fd, buf);
        fs.closeSync(fd);
        closed = true;
    } catch (e) {
        if (!closed) {
            fs.closeSync(fd);
        }
    }
}
