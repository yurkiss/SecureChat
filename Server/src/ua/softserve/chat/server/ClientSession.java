/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.softserve.chat.server;

import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.SecretKey;

/**
 *
 * @author yrid
 */
public class ClientSession {

    public final int id;
    public final OutputStream out;
    public final InputStream in;
    public final SecretKey sharedSecretKey;
    private static int clientsCounter;

    public ClientSession(OutputStream out, InputStream in, SecretKey sharedSecretKey) {        
        this.id = ++clientsCounter;
        this.out = out;
        this.in = in;
        this.sharedSecretKey = sharedSecretKey;
    }

}
