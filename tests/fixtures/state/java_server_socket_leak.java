import java.net.*;

class Server {
    void startUnsafe(int port) {
        ServerSocket server = new ServerSocket(port);
        server.accept();
        // server never closed — leak
    }
}
