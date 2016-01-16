/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.softserve.chat.server;

import ua.softserve.chat.security.EncodedReader;
import ua.softserve.chat.security.EncodedWriter;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author yrid
 */
public class ReceivingThread extends Thread {

    private final SecretKey mSharedSecretKey;
    private final String mSymChipherAlgorythm;
    private final ClientSession mCurrentSession;

    private static final Logger LOG = Logger.getLogger(ReceivingThread.class.getName());

    public ReceivingThread(SecretKey sharedSecretKey, String symChipherAlgorythm, ClientSession client) {
        this.mSharedSecretKey = sharedSecretKey;
        this.mSymChipherAlgorythm = symChipherAlgorythm;
        this.mCurrentSession = client;
    }

    @Override
    public void run() {

        if (mCurrentSession != null) {
            readEncodedMessages(mCurrentSession.in);
        }

    }

    private void readEncodedMessages(InputStream in) {
        try {
            //Read client's massages
            String str;
            EncodedReader reader = new EncodedReader(in, mSymChipherAlgorythm, mSharedSecretKey);
            while ((str = reader.read()) != null) {

                //Send messages to all clients except sender
                Server server = Server.getInstance();
                for (ClientSession clientSession : server.mClients) {
                    if (clientSession != mCurrentSession) {
                        EncodedWriter encodedWriter = new EncodedWriter(mSymChipherAlgorythm, clientSession.sharedSecretKey);
                        encodedWriter.writeLine(str);
                        encodedWriter.sendTo(clientSession.out);
                        System.out.println("Send message to client id: " + clientSession.id);
                    }
                }

                System.out.println("That side said: " + str);
                System.out.print(">");
                System.out.flush();
            }
        } catch (java.net.SocketException ex) {
            System.out.println("That side disconected.");
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
    }

}
