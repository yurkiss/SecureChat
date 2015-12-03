package ua.softserve.chat.nio;

import ua.softserve.chat.security.EncodedWriter;
import ua.softserve.chat.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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


    public void start(){

        try {
            System.out.println("Connecting...");
            SocketChannel socketChannel = SocketChannel.open();
            socketChannel.configureBlocking(false);
            socketChannel.connect(new InetSocketAddress(mServerAddress, mServerPort));

            while(! socketChannel.finishConnect() ){
                //wait, or do something else...
                System.out.print(".");
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            try (BufferedReader systemIn = new BufferedReader(new InputStreamReader(System.in));) {

                System.out.print(">");
                String string = null;

                while ((string = systemIn.readLine()) != null) {

                    ByteBuffer buffer = Charset.defaultCharset().encode(string);
                    buffer.position(buffer.capacity());
                    buffer.flip();
                    while(buffer.hasRemaining()) {
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

        if(args.length == 2){
            NIOClient client = new NIOClient(args[0], Integer.parseInt(args[1]), Security.UNSECURE);
            client.start();
        }else{
            NIOClient client = new NIOClient("127.0.0.1", Integer.parseInt("8084"), Security.UNSECURE);
            client.start();
        }

    }
}
