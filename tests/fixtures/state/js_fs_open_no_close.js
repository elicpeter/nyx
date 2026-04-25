function fileLeak() {
    const fd = fs.openSync("data.txt", "r");
    // Missing fs.closeSync(fd) — resource leak
}
