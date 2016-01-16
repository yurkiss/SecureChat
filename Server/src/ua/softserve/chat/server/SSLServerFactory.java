package ua.softserve.chat.server;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

public class SSLServerFactory extends AbstractServerFactory implements ServerFactory {

    @Override
    public ServerSocketFactory getServerSocketFactory() {
        return SSLServerSocketFactory.getDefault();
    }
}
