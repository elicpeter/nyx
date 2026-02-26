var fs = require('fs');

function doubleClose(path) {
    var fd = fs.openSync(path, 'r');
    fs.closeSync(fd);
    fs.closeSync(fd); // double close!
}

function useAfterClose(path) {
    var fd = fs.openSync(path, 'r');
    fs.closeSync(fd);
    var buf = Buffer.alloc(1024);
    fs.readSync(fd, buf); // use after close!
}
