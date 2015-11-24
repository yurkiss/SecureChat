/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.softserve.chat.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

/**
 *
 * @author yrid
 */
public interface ServerFactory {

    ServerSocketFactory getServerSocketFactory();

    ServerSocket createServerSocket(ServerSocketFactory serverFactory, int portNumber) throws IOException;

    Socket acceptSocket(ServerSocket serverSocket) throws IOException;
}

