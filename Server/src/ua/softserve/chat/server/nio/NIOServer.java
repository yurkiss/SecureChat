/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ua.softserve.chat.server.nio;

import ua.softserve.chat.security.Security;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;



/**
 * @author User
 */
public class NIOServer {

    private static volatile NIOServer instance;

    private PublicKey mPublicKey;
    private PrivateKey mPrivateKey;

    private static int clientsCounter;
    public volatile List<SSLChannelSession> mClients;

    private static final Logger LOG = Logger.getLogger(NIOServer.class.getName());
    private static final String SYM_CHIPHER_ALGORYTHM_NAME = "AES/ECB/PKCS5Padding";
    private static final String ASYM_CHIPHER_ALGORYTHM_NAME = "RSA/ECB/PKCS1Padding";
    private static final String KEY_MISSING_EXCEPTION = "Shared key missing exception!";

    private SSLContext sslContext;
    private final int port;

    public static NIOServer getInstance(int port) {
        return getInstance(Security.UNSECURE, port);
    }

    public static synchronized NIOServer getInstance(Security security, int port) {
        if (instance == null) {
            instance = new NIOServer(security, port);
        }
        return instance;
    }

    private NIOServer(int port) {
        this(Security.UNSECURE, port);
    }

    private NIOServer(Security security, int port) {

        switch (security) {
            case SSL:
                initKeyStores();
                break;
            case UNSECURE:
                break;
            default:
                break;
        }

        this.port = port;
    }


    void initKeyStores() {
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

            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);


        } catch (IOException | CertificateException | UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
    }


    /**
     * NIOServer starts here
     */
    public void start() {

        try {

            //Starting server
            ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
            serverSocketChannel.configureBlocking(false);

            ServerSocket serverSocket = serverSocketChannel.socket();
            serverSocket.bind(new InetSocketAddress(port));
            System.out.println("NIOServer started.");

            //Open selector
            Selector selector = Selector.open();
            Selector readSelector = Selector.open();
            Selector writeSelector = Selector.open();

            serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

            BlockingQueue<String> messagesQueue = new LinkedBlockingQueue<>();


            Thread thread = new Thread(new Runnable() {

                @Override
                public void run() {
                    try {

                        //Start selection
                        while (true) {
                            int readyChannels = readSelector.selectNow();
                            if (readyChannels > 0) {

                                Set<SelectionKey> selectionKeys = readSelector.selectedKeys();
                                Iterator<SelectionKey> iterator = selectionKeys.iterator();

                                while (iterator.hasNext()) {
                                    SelectionKey key = iterator.next();

                                    if (key.isReadable()) {
                                        SSLChannelSession session = (SSLChannelSession) key.attachment();

                                        ByteBuffer buf = ByteBuffer.allocate(1024);
                                        int count = session.read(buf);
                                        buf.flip();
                                        CharBuffer charBuffer = Charset.defaultCharset().decode(buf);
                                        String str = charBuffer.toString();
                                        System.out.println("Read " + count + " bytes from #" + session.id + ": " + str);
                                        messagesQueue.put(str);

                                        iterator.remove();
                                    }

                                }

                            }

                            if (!messagesQueue.isEmpty()) {

                                readyChannels = readSelector.selectNow();
                                if (readyChannels > 0) {
                                    Set<SelectionKey> selectionKeys = readSelector.selectedKeys();
                                    Iterator<SelectionKey> iterator = selectionKeys.iterator();

                                    while (!messagesQueue.isEmpty()) {
                                        String message = messagesQueue.poll();

                                        while (iterator.hasNext()) {
                                            SelectionKey key = iterator.next();
                                            if (key.isWritable()) {

                                                SSLChannelSession session = (SSLChannelSession) key.attachment();

                                                ByteBuffer buffer = Charset.defaultCharset().encode(message);
                                                buffer.position(buffer.capacity());
                                                buffer.flip();
                                                int count = session.write(buffer);
                                                System.out.println("Sent " + count + " bytes to #" + session.id);

                                                iterator.remove();

                                            }
                                        }
                                    }

                                }
                            }
                            Thread.sleep(100);
                        }

                    } catch (IOException | InterruptedException e) {
                        LOG.log(Level.SEVERE, null, e);
                    }


                }
            });
            thread.start();

            try {
                while (true) {

                    int readyChannels = selector.select();
                    if (readyChannels > 0) {

                        Set<SelectionKey> selectionKeys = selector.selectedKeys();
                        Iterator<SelectionKey> iterator = selectionKeys.iterator();

                        while (iterator.hasNext()) {
                            SelectionKey key = iterator.next();

                            if (key.isAcceptable()) {
                                ServerSocketChannel srv = (ServerSocketChannel) key.channel();
                                SocketChannel socketChannel = srv.accept();
                                if (socketChannel != null) {
                                    socketChannel.configureBlocking(false);
                                    SSLChannelSession session = new SSLChannelSession(socketChannel, sslContext);
                                    socketChannel.register(readSelector, SelectionKey.OP_READ | SelectionKey.OP_WRITE, session);
                                    //socketChannel.register(writeSelector, SelectionKey.OP_WRITE, session);
                                    System.out.println("Accepted connection from " + socketChannel.getRemoteAddress());
                                }
                            }

                            iterator.remove();
                        }

                    }
                }
            } catch (IOException e) {
                LOG.log(Level.SEVERE, null, e);
            }


        } catch (IOException e) {
            LOG.log(Level.SEVERE, null, e);
        }

    }

//                // Create the engine
//                SSLEngine engine = sslContext.createSSLEngine(hostname, port);
//                // Use as client
//                engine.setUseClientMode(false);
    //do something with socketChannel...


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
        NIOServer server = NIOServer.getInstance(Security.UNSECURE, 8084);
        server.start();
    }

}

