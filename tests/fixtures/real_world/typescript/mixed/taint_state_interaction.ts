import * as fs from 'fs';

function processUserFile(userPath: string): string {
    var fd = fs.openSync(userPath, 'r'); // taint: userPath is user-controlled
    var buf = Buffer.alloc(4096);
    var bytesRead = fs.readSync(fd, buf);
    if (bytesRead === 0) {
        // early return leaks fd
        return 'empty';
    }
    fs.closeSync(fd);
    return buf.slice(0, bytesRead).toString();
}

function processUserFileSafe(userPath: string): string {
    var fd = fs.openSync(userPath, 'r');
    try {
        var buf = Buffer.alloc(4096);
        var bytesRead = fs.readSync(fd, buf);
        if (bytesRead === 0) {
            return 'empty';
        }
        return buf.slice(0, bytesRead).toString();
    } finally {
        fs.closeSync(fd);
    }
}
