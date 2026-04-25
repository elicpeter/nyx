function connectUnsafe(url) {
    var ws = new WebSocket(url);
    ws.send('hello');
    // ws never closed — leak
}
