var fs = require('fs');

function useAfterCloseRead() {
    var fd = fs.openSync("data.txt", "r");
    fs.closeSync(fd);
    var buf = Buffer.alloc(1024);
    fs.readSync(fd, buf); // use after close!
}
