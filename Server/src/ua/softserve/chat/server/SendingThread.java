/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.softserve.chat.server;

import ua.softserve.chat.security.EncodedWriter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author yrid
 */
public class SendingThread extends Thread{
    
    private final SecretKey mSharedSecretKey;
    private final String mSymChipherAlgorythm;
    private final OutputStream mOs;

    private static final Logger LOG = Logger.getLogger(SendingThread.class.getName());

    public SendingThread(SecretKey sharedSecretKey, String symChipherAlgorythm, OutputStream os) {
        this.mSharedSecretKey = sharedSecretKey;
        this.mSymChipherAlgorythm = symChipherAlgorythm;
        this.mOs = os;
    }
   
    @Override
    public void run() {
        try (BufferedReader systemIn = new BufferedReader(new InputStreamReader(System.in));) {

            EncodedWriter encodedWriter = new EncodedWriter(mSymChipherAlgorythm, mSharedSecretKey);

            System.out.print(">");
            String string = null;

            while ((string = systemIn.readLine()) != null) {
                
                encodedWriter.writeLine(string);
                encodedWriter.sendTo(mOs);

                System.out.print(">");
            }

        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }

    }
}
