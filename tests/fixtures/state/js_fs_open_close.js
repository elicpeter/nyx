function fileClean() {
    const fd = fs.openSync("data.txt", "r");
    fs.closeSync(fd);
}
