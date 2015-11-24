package ua.softserve.chat.server;

import javax.net.ServerSocketFactory;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public abstract class AbstractServerFactory implements ServerFactory {

    @Override
    public ServerSocket createServerSocket(ServerSocketFactory serverSocketFactory, int portNumber) throws IOException {
        return serverSocketFactory.createServerSocket(portNumber);
    }

    @Override
    public Socket acceptSocket(ServerSocket serverSocket) throws IOException {
        return serverSocket.accept();
    }
}
