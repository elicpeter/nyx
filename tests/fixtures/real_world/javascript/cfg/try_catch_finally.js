var fs = require('fs');

function processFile(path) {
    var fd;
    try {
        fd = fs.openSync(path, 'r');
        var data = fs.readFileSync(fd, 'utf8');
        return data;
    } catch (e) {
        console.error(e);
    } finally {
        if (fd !== undefined) {
            fs.closeSync(fd);
        }
    }
}

function leakyProcess(path) {
    var fd = fs.openSync(path, 'r');
    var data = fs.readFileSync(fd, 'utf8');
    if (data.length === 0) {
        throw new Error('empty');
    }
    fs.closeSync(fd);
    return data;
}
