function fileClean(path: string): void {
    var fd = fs.openSync(path, 'r');
    var buf = Buffer.alloc(1024);
    fs.readSync(fd, buf);
    fs.closeSync(fd);
}
