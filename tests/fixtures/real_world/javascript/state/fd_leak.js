var fs = require('fs');

function readAndProcess(path) {
    var fd = fs.openSync(path, 'r');
    var buf = Buffer.alloc(1024);
    fs.readSync(fd, buf);
    // Missing: fs.closeSync(fd)
    return buf.toString();
}

function readAndClose(path) {
    var fd = fs.openSync(path, 'r');
    var buf = Buffer.alloc(1024);
    fs.readSync(fd, buf);
    fs.closeSync(fd);
    return buf.toString();
}
