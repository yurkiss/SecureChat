/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.softserve.chat.client;

import ua.softserve.chat.security.EncodedReader;
import ua.softserve.chat.security.Security;

import javax.crypto.*;
import javax.net.SocketFactory;
import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author User
 */
public class Client {

    private static final Logger LOG = Logger.getLogger(Client.class.getName());
    private static final String SYM_CHIPHER_ALGORYTHM_NAME = "AES/ECB/PKCS5Padding";
    private static final String ASYM_CHIPHER_ALGORYTHM_NAME = "RSA/ECB/PKCS1Padding";

    private final ClientFactory mClientFactory;
    private SecretKey mSecretAESKey;
    
    private final String mServerAddress;
    private final int mServerPort;

    public Client(String ip, int port) {
        this(ip, port, Security.UNSECURE);
    }

    public Client(String ip, int port, Security security) {

        switch (security) {
            case SSL:
                System.setProperty("javax.net.ssl.keyStore", "C:/Users/yrid/IdeaProjects/SecureChat/myClientKeyStore");
                System.setProperty("javax.net.ssl.keyStorePassword", "12345678");
                System.setProperty("javax.net.ssl.trustStore", "C:/Users/yrid/IdeaProjects/SecureChat/myClientTrustStore");
                System.setProperty("javax.net.ssl.trustStorePassword", "12345678");
                mClientFactory = new SSLClientFactory();
                break;
            case UNSECURE:
                mClientFactory = new UnsecureClientFactory();
                break;
            default:
                mClientFactory = new UnsecureClientFactory();
                break;
        }        
        
        mServerAddress = ip;
        mServerPort = port;
    }

    public void start() {

        SocketFactory socketFactory = mClientFactory.getSocketFactory();

        try (Socket socket = mClientFactory.createSocket(socketFactory, mServerAddress, mServerPort);) {

            //Send messages to server
            OutputStream os = socket.getOutputStream();

            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            String step = in.readUTF();
            if (step.equals("KEY")) {
                int keySize = in.readInt();
                byte[] keyBytes = new byte[keySize];
                if (in.read(keyBytes) > 0) {
                    EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(keyBytes);
                    KeyFactory instance = KeyFactory.getInstance("RSA");
                    PublicKey serverPublicKey = instance.generatePublic(encodedKeySpec);

                    KeyGenerator keygen = KeyGenerator.getInstance("AES");
                    keygen.init(256);
                    mSecretAESKey = keygen.generateKey();

                    Cipher secretCipher = Cipher.getInstance(ASYM_CHIPHER_ALGORYTHM_NAME);
                    secretCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
                    byte[] encryptedSecret = secretCipher.doFinal(mSecretAESKey.getEncoded());

                    System.out.println(Arrays.toString(mSecretAESKey.getEncoded()));

                    DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(os));

                    dos.writeUTF("SECRET_KEY");
                    dos.writeInt(encryptedSecret.length);
                    dos.write(encryptedSecret);
                    dos.flush();

                }
            }

            Thread thread = new SendingThread(mSecretAESKey, SYM_CHIPHER_ALGORYTHM_NAME, os);
            thread.setDaemon(true);
            thread.start();
            

            //Read server messages            
            //Thread recvThread = new ReceivingThread(mSecretAESKey, SYM_CHIPHER_ALGORYTHM_NAME, socket.getInputStream());
            //recvThread.start();
            readEncodedMessages(socket.getInputStream());

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidKeyException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
    }

    private void readEncodedMessages(InputStream in) {
        try {
            //Read client's massages
            String str;
            EncodedReader reader = new EncodedReader(in, SYM_CHIPHER_ALGORYTHM_NAME, mSecretAESKey);
            while ((str = reader.read()) != null) {
                System.out.println("Received: " + str);
                System.out.print(">");
                System.out.flush();
            }
        } catch (SocketException ex) {
            System.out.println("Server closed socket. Bye.");            
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | IOException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
    }

    public static void main(String[] args) {
        if(args.length == 2){
            Client client = new Client(args[0], Integer.parseInt(args[1]), Security.UNSECURE);
            client.start();           
        }else{
            Client client = new Client("127.0.0.1", Integer.parseInt("8084"), Security.UNSECURE);
            client.start();            
        }

    }

}
