package ua.softserve.chat.nio;

import ua.softserve.chat.security.Security;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by yrid on 30.11.2015.
 */
public class NIOClient {

    private static final Logger LOG = Logger.getLogger(NIOClient.class.getName());
    private static final String SYM_CHIPHER_ALGORYTHM_NAME = "AES/ECB/PKCS5Padding";
    private static final String ASYM_CHIPHER_ALGORYTHM_NAME = "RSA/ECB/PKCS1Padding";

    private SecretKey mSecretAESKey;
    private final String mServerAddress;
    private final int mServerPort;

    public NIOClient(String mServerAddress, int mServerPort, Security security) {
        this.mServerAddress = mServerAddress;
        this.mServerPort = mServerPort;
    }


    public void start() {

        try {
            System.out.println("Connecting...");
            SocketChannel socketChannel = SocketChannel.open();
            socketChannel.configureBlocking(false);
            socketChannel.connect(new InetSocketAddress(mServerAddress, mServerPort));

            while (!socketChannel.finishConnect()) {
                //wait, or do something else...
                System.out.print(".");
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            Selector selector = Selector.open();
            socketChannel.register(selector, SelectionKey.OP_READ);

            Thread receivingThread = new Thread() {
                @Override
                public void run() {

                    try {

                        ByteBuffer byteBuffer = ByteBuffer.allocate(1024);
                        while (true) {

                            int readyChannels = selector.select();
                            if (readyChannels > 0) {

                                Set<SelectionKey> selectionKeys = selector.selectedKeys();
                                Iterator<SelectionKey> iterator = selectionKeys.iterator();

                                while (iterator.hasNext()) {
                                    SelectionKey key = iterator.next();
                                    if (key.isValid() && key.isReadable()) {

                                        int bytesRead = 0;

                                        SocketChannel channel = (SocketChannel) key.channel();

                                        bytesRead = channel.read(byteBuffer);
                                        int totalBytesRead = bytesRead;

                                        while (bytesRead > 0) {
                                            bytesRead = channel.read(byteBuffer);
                                            totalBytesRead += bytesRead;
                                        }

                                        if (bytesRead == -1) {
                                            //this.endOfStreamReached = true;
                                            System.out.println("Server closed connection. Bye.");
                                            return;
                                        }

                                        if (totalBytesRead > 0) {
                                            byteBuffer.flip();
                                            CharBuffer charBuffer = Charset.defaultCharset().decode(byteBuffer);
                                            String str = charBuffer.toString();
                                            //System.out.println("Receive " + totalBytesRead + " bytes from server: " + str);
                                            System.out.println("Server: " + str);
                                            byteBuffer.clear();
                                        }

                                    }
                                    iterator.remove();
                                }

                            }


                        }
                    } catch (IOException e) {
                        LOG.log(Level.SEVERE, null, e);
                    }
                }
            };
            receivingThread.start();

            try (BufferedReader systemIn = new BufferedReader(new InputStreamReader(System.in));) {

                System.out.print(">");
                String string = null;

                while ((string = systemIn.readLine()) != null) {

                    ByteBuffer buffer = Charset.defaultCharset().encode(string);
                    buffer.position(buffer.capacity());
                    buffer.flip();
                    while (buffer.hasRemaining()) {
                        socketChannel.write(buffer);
                    }
                    System.out.print(">");
                }

            } catch (IOException ex) {
                LOG.log(Level.SEVERE, null, ex);
            }


        } catch (IOException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }

    }

    public static void main(String[] args) {

        if (args.length == 2) {
            NIOClient client = new NIOClient(args[0], Integer.parseInt(args[1]), Security.UNSECURE);
            client.start();
        } else {
            NIOClient client = new NIOClient("127.0.0.1", Integer.parseInt("8084"), Security.UNSECURE);
            client.start();
        }

    }
}
