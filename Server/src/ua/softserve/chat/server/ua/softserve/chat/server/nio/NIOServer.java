/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.softserve.chat.server.ua.softserve.chat.server.nio;

import ua.softserve.chat.security.Security;
import ua.softserve.chat.server.*;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;


class ClientSession {

    public int id;
    private SocketChannel socketChannel;
    private boolean endOfStreamReached;

    private static int sCounter;

    public ClientSession(SocketChannel channel) {
        this.socketChannel = channel;
        this.id = sCounter++;
    }

    public int read(ByteBuffer byteBuffer) throws IOException {
        int bytesRead = socketChannel.read(byteBuffer);
        int totalBytesRead = bytesRead;

        while(bytesRead > 0){
            bytesRead = socketChannel.read(byteBuffer);
            totalBytesRead += bytesRead;
        }

        if(bytesRead == -1){
            this.endOfStreamReached = true;
        }

        return totalBytesRead;
    }

    public int write(ByteBuffer byteBuffer) throws IOException{
        int bytesWritten      = socketChannel.write(byteBuffer);
        int totalBytesWritten = bytesWritten;

        while(bytesWritten > 0 && byteBuffer.hasRemaining()){
            bytesWritten = socketChannel.write(byteBuffer);
            totalBytesWritten += bytesWritten;
        }

        return totalBytesWritten;
    }

}

/**
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

        try {

            char[] passphrase = "12345678".toCharArray();

            // First initialize the key and trust material
            KeyStore ksKeys = KeyStore.getInstance("JKS");
            ksKeys.load(new FileInputStream("C:/Users/yrid/IdeaProjects/SecureChat/mySrvKeyStore"), passphrase);
            KeyStore ksTrust = KeyStore.getInstance("JKS");
            ksTrust.load(new FileInputStream("C:/Users/yrid/IdeaProjects/SecureChat/mySrvTrustStore"), passphrase);

            // KeyManagers decide which key material to use
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ksKeys, passphrase);

            // TrustManagers decide whether to allow connections
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ksTrust);


            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            String hostname = "127.0.0.1";
            int port = 8084;

            //Starting server
            ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.configureBlocking(false);

            ServerSocket serverSocket = serverSocketChannel.socket();
            serverSocket.bind(new InetSocketAddress(port));
            System.out.println("NIOServer started.");

            //Open selector
            Selector selector = Selector.open();

            SelectionKey selectionKey = serverSocketChannel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);


            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        while (true) {

                            SocketChannel socketChannel = serverSocketChannel.accept();
                            if (socketChannel != null) {
                                socketChannel.configureBlocking(false);
                                socketChannel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
                            }
                        }
                    } catch (IOException e) {
                        LOG.log(Level.SEVERE, null, e);
                    }

                }
            });



            //Start selection
            while (true) {
                int readyChannels = selector.select();
                if (readyChannels > 0) {
                    Set<SelectionKey> selectionKeys = selector.selectedKeys();
                    Iterator<SelectionKey> iterator = selectionKeys.iterator();

                    while (iterator.hasNext()) {
                        SelectionKey key = iterator.next();

                        //ClientSession attachment = (ClientSession) key.attachment();

                        if (key.isReadable()) {

                        } else if (key.isWritable()) {

                        }

                        iterator.remove();
                    }

                }
            }


        } catch (NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException | KeyStoreException | IOException | KeyManagementException e) {
            LOG.log(Level.SEVERE, null, e);
        }

    }

//                // Create the engine
//                SSLEngine engine = sslContext.createSSLEngine(hostname, port);
//                // Use as client
//                engine.setUseClientMode(false);
    //do something with socketChannel...


    void doHandshake(SocketChannel socketChannel, SSLEngine engine,
                     ByteBuffer myNetData, ByteBuffer peerNetData) throws Exception {

        // Create byte buffers to use for holding application data
        int appBufferSize = engine.getSession().getApplicationBufferSize();
        ByteBuffer myAppData = ByteBuffer.allocate(appBufferSize);
        ByteBuffer peerAppData = ByteBuffer.allocate(appBufferSize);

        // Begin handshake
        engine.beginHandshake();
        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();

        // Process handshaking message
        while (hs != SSLEngineResult.HandshakeStatus.FINISHED &&
                hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

            switch (hs) {

                case NEED_UNWRAP:
                    // Receive handshaking data from peer
                    if (socketChannel.read(peerNetData) < 0) {
                        // The channel has reached end-of-stream
                    }

                    // Process incoming handshaking data
                    peerNetData.flip();
                    SSLEngineResult res = engine.unwrap(peerNetData, peerAppData);
                    peerNetData.compact();
                    hs = res.getHandshakeStatus();

                    // Check status
                    switch (res.getStatus()) {
                        case OK:
                            // Handle OK status
                            break;

                        // Handle other status: BUFFER_UNDERFLOW, BUFFER_OVERFLOW, CLOSED
                        //...
                    }
                    break;

                case NEED_WRAP:
                    // Empty the local network packet buffer.
                    myNetData.clear();

                    // Generate handshaking data
                    res = engine.wrap(myAppData, myNetData);
                    hs = res.getHandshakeStatus();

                    // Check status
                    switch (res.getStatus()) {
                        case OK:
                            myNetData.flip();

                            // Send the handshaking data to peer
                            while (myNetData.hasRemaining()) {
                                socketChannel.write(myNetData);
                            }
                            break;

                        // Handle other status:  BUFFER_OVERFLOW, BUFFER_UNDERFLOW, CLOSED
                        //...
                    }
                    break;

                case NEED_TASK:
                    // Handle blocking tasks
                    break;

                // Handle other status:  // FINISHED or NOT_HANDSHAKING
                //...
            }
        }

        // Processes after handshaking
        //...
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
