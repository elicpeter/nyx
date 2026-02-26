var net = require('net');

function startServer() {
    var connections = [];
    var server = net.createServer(function(socket) {
        connections.push(socket);
        socket.on('data', function(data) {
            handleData(socket, data);
        });
        // Missing: socket.on('close', ...) cleanup
        // Missing: socket.on('error', ...) cleanup
    });
    server.listen(3000);
}

function startServerSafe() {
    var connections = [];
    var server = net.createServer(function(socket) {
        connections.push(socket);
        socket.on('data', function(data) {
            handleData(socket, data);
        });
        socket.on('close', function() {
            var idx = connections.indexOf(socket);
            if (idx !== -1) {
                connections.splice(idx, 1);
            }
        });
        socket.on('error', function(err) {
            console.error('Socket error:', err);
            socket.destroy();
        });
    });
    server.listen(3000);
}

function handleData(socket, data) {
    socket.write('echo: ' + data.toString());
}
