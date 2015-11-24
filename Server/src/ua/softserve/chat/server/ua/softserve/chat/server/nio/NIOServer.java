/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.softserve.chat.server.ua.softserve.chat.server.nio;

import ua.softserve.chat.security.Security;
import ua.softserve.chat.server.*;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;

/**
 *
 * @author User
 */
public class NIOServer {

    private final ServerFactory mServerSecurityFactory;

    private static volatile NIOServer instance;

    private PublicKey mPublicKey;
    private PrivateKey mPrivateKey;

    private static int clientsCounter;
    public volatile List<ClientSession> mClients;

    private static final Logger LOG = Logger.getLogger(NIOServer.class.getName());
    private static final String SYM_CHIPHER_ALGORYTHM_NAME = "AES/ECB/PKCS5Padding";
    private static final String ASYM_CHIPHER_ALGORYTHM_NAME = "RSA/ECB/PKCS1Padding";
    private static final String KEY_MISSING_EXCEPTION = "Shared key missing exception!";


    public static NIOServer getInstance() {
        return getInstance(Security.UNSECURE);
    }

    public static synchronized NIOServer getInstance(Security security) {
        if (instance == null) {
            instance = new NIOServer(security);
        }
        return instance;
    }

    private NIOServer() {
        this(Security.UNSECURE);
    }

    private NIOServer(Security security) {

        switch (security) {
            case SSL:
                System.setProperty("javax.net.ssl.keyStore", "C:/Users/yrid/IdeaProjects/SecureChat/mySrvKeyStore");
                System.setProperty("javax.net.ssl.keyStorePassword", "12345678");
                System.setProperty("javax.net.ssl.trustStore", "C:/Users/yrid/IdeaProjects/SecureChat/mySrvTrustStore");
                System.setProperty("javax.net.ssl.trustStorePassword", "12345678");

                mServerSecurityFactory = new SSLServerFactory();
                break;
            case UNSECURE:
                mServerSecurityFactory = new UnsecureServerFactory();
                break;
            default:
                mServerSecurityFactory = new UnsecureServerFactory();
                break;
        }
    }

    /**
     * NIOServer starts here
     */
    public void start() {

        ServerSocketFactory socketFactory = mServerSecurityFactory.getServerSocketFactory();

        try {

            ServerSocket serverSocket = mServerSecurityFactory.createServerSocket(socketFactory, 8084);
            mClients = new LinkedList<>();

            init();

            System.out.println("NIOServer started.");

            while (true) {
                try {
                    Socket socket = mServerSecurityFactory.acceptSocket(serverSocket);
                    System.out.println("New client connected.");
                    clientsCounter++;

                    final InputStream inputStream = socket.getInputStream();
                    final OutputStream outputStream = socket.getOutputStream();

                    //Send public key to client
                    sendPublicKey(outputStream);

                    SecretKey sharedSecretKey = receiveSharedSecretKey(inputStream);
                    System.out.println(Arrays.toString(sharedSecretKey.getEncoded()));

                    if (sharedSecretKey == null) {
                        System.out.println(KEY_MISSING_EXCEPTION);
                        DataOutputStream os = new DataOutputStream(new BufferedOutputStream(outputStream));
                        os.writeUTF(KEY_MISSING_EXCEPTION);
                        os.flush();
                        socket.close();
                        continue;
                    }
                    
                    final ClientSession clientSession = new ClientSession(outputStream, inputStream, sharedSecretKey);
                    mClients.add(clientSession);

                    //Send messages to client
                    Thread thread = new SendingThread(sharedSecretKey, SYM_CHIPHER_ALGORYTHM_NAME, outputStream);
                    thread.setDaemon(true);
                    thread.start();

                    Thread recvThread = new ReceivingThread(sharedSecretKey, SYM_CHIPHER_ALGORYTHM_NAME, clientSession);
                    recvThread.setDaemon(true);
                    recvThread.start();

                    //readEncodedMessages(inputStream);
                } catch (IOException ex) {
                    LOG.log(Level.SEVERE, null, ex);
                }

            }

        } catch (IOException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }

    }

    private SecretKey receiveSharedSecretKey(InputStream is) {
        try {
            //Receiving encrypted shared secret key
            DataInputStream in = new DataInputStream(new BufferedInputStream(is));
            String step = in.readUTF();
            SecretKey secretKey = null;
            if (step.equals("SECRET_KEY")) {
                int keySize = in.readInt();
                byte[] encryptedKeyBytes = new byte[keySize];
                if (in.read(encryptedKeyBytes) > 0) {

                    //Decrypting shared secret key
                    Cipher cipher = Cipher.getInstance(ASYM_CHIPHER_ALGORYTHM_NAME);
                    cipher.init(Cipher.DECRYPT_MODE, mPrivateKey);
                    byte[] sharedKeyBytes = cipher.doFinal(encryptedKeyBytes);

                    secretKey = new SecretKeySpec(sharedKeyBytes, "AES");
                }
            }
            return secretKey;
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private void sendPublicKey(OutputStream out) throws IOException {

        DataOutputStream os = new DataOutputStream(new BufferedOutputStream(out));
        os.writeUTF("KEY");
        byte[] keyBytes = mPublicKey.getEncoded();
        os.writeInt(keyBytes.length);
        os.write(keyBytes);
        os.flush();
    }

    private void init() {
        try {
            //Generating key pair for asymetric encrypting
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(4096);
            KeyPair key = keyGen.generateKeyPair();

            mPublicKey = key.getPublic();
            mPrivateKey = key.getPrivate();

        } catch (NoSuchAlgorithmException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
    }

//    private void readEncodedMessages(InputStream in) {
//        try {
//            //Read client's massages
//            String str;
//            EncodedReader reader = new EncodedReader(in, SYM_CHIPHER_ALGORYTHM_NAME, mSharedSecretKey);
//            while ((str = reader.read()) != null) {
//                System.out.println("Client said: " + str);
//                System.out.print(">");
//                System.out.flush();
//            }
//        } catch (java.net.SocketException ex) {
//            System.out.println("Client disconected.");
//        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
//            LOG.log(Level.SEVERE, null, ex);
//        }
//    }
    public static void main(String[] args) {
        NIOServer server = NIOServer.getInstance(Security.UNSECURE);
        server.start();
    }

}

/*
private static SSLServerSocketFactory getServerSocketFactory(String type) {

        if (type.equals("TLS")) {
            SSLServerSocketFactory ssf = null;
            try {
                // set up key manager to do server authentication
                SSLContext ctx;
                KeyManagerFactory kmf;
                KeyStore ks;
                char[] passphrase = "passphrase".toCharArray();

                ctx = SSLContext.getInstance(type);
                kmf = KeyManagerFactory.getInstance("SunX509");
                ks = KeyStore.getInstance("JKS");

                ks.load(new FileInputStream("testkeys"), passphrase);
                kmf.init(ks, passphrase);
                ctx.init(kmf.getKeyManagers(), null, null);

                ssf = ctx.getServerSocketFactory();
                return ssf;
            

} catch (Exception e) {
                Logger.getLogger(NIOServer.class
.getName()).log(Level.SEVERE, null, e);
            }
        } else {
            return (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        }
        return null;
    }
 */
