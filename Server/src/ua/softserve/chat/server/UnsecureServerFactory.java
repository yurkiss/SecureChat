package ua.softserve.chat.server;

import javax.net.ServerSocketFactory;

public class UnsecureServerFactory extends AbstractServerFactory implements ServerFactory {

    @Override
    public ServerSocketFactory getServerSocketFactory() {
        return ServerSocketFactory.getDefault();
    }
}
