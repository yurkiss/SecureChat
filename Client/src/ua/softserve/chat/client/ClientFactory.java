/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.softserve.chat.client;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.Socket;

public interface ClientFactory {

    SocketFactory getSocketFactory();

    Socket createSocket(SocketFactory factory, String host, int portNumber) throws IOException;

}

abstract class AbstractClientFactory implements ClientFactory {

    @Override
    public Socket createSocket(SocketFactory socketFactory, String host, int portNumber) throws IOException {
        return socketFactory.createSocket(host, portNumber);
    }
}

class SSLClientFactory extends AbstractClientFactory implements ClientFactory {

    @Override
    public SocketFactory getSocketFactory() {
        return SSLSocketFactory.getDefault();
    }
}

class UnsecureClientFactory extends AbstractClientFactory implements ClientFactory {

    @Override
    public SocketFactory getSocketFactory() {
        return SocketFactory.getDefault();
    }
}
