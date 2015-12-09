package ua.softserve.chat.server.nio;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

/**
 * Created by yrid on 09.12.2015.
 */
public class SSLChannelSession {

    private static int sCounter;

    public int id;

    private SocketChannel socketChannel;
    private boolean endOfStreamReached;

    private SSLSession session;
    private final SSLEngine engine;

    //input from pear
    private final ByteBuffer peerNetData;
    private final ByteBuffer peerAppData;

    //output from server
    private final ByteBuffer outAppData;
    private final ByteBuffer outNetData;

    private boolean handshacking = false;
    private SSLEngineResult.HandshakeStatus handshakeStatus;


    public SSLChannelSession(SocketChannel channel, SSLContext sslContext ) {
        this.socketChannel = channel;
        this.id = sCounter++;
        String hostname = "127.0.0.1";
        int port = 8084;

        // Create the engine
        this.engine = sslContext.createSSLEngine(hostname, port);

        // Use as client
        engine.setUseClientMode(false);

        // Create byte buffers to use for holding application and encoded data
        session = engine.getSession();

        outAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
        outNetData = ByteBuffer.allocate(session.getPacketBufferSize());
        peerAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
        peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());

    }


    public int read(ByteBuffer byteBuffer) throws IOException {
        int bytesRead = socketChannel.read(byteBuffer);
        int totalBytesRead = bytesRead;

        while (bytesRead > 0) {
            bytesRead = socketChannel.read(byteBuffer);
            totalBytesRead += bytesRead;
        }

        if (bytesRead == -1) {
            this.endOfStreamReached = true;
        }

        return totalBytesRead;
    }

    public int write(ByteBuffer byteBuffer) throws IOException {
        int bytesWritten = socketChannel.write(byteBuffer);
        int totalBytesWritten = bytesWritten;

        while (bytesWritten > 0 && byteBuffer.hasRemaining()) {
            bytesWritten = socketChannel.write(byteBuffer);
            totalBytesWritten += bytesWritten;
        }

        return totalBytesWritten;
    }


    void doHandshake(SocketChannel socketChannel, SSLEngine engine,
                     ByteBuffer myNetData, ByteBuffer peerNetData) throws Exception {

        // Create byte buffers to use for holding application data
        int appBufferSize = engine.getSession().getApplicationBufferSize();
        ByteBuffer myAppData = ByteBuffer.allocate(appBufferSize);
        ByteBuffer peerAppData = ByteBuffer.allocate(appBufferSize);

        // Begin handshake
        engine.beginHandshake();
        handshakeStatus = engine.getHandshakeStatus();

        // Process handshaking message
        while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED &&
                handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

            switch (handshakeStatus) {

                case NEED_UNWRAP:
                    // Receive handshaking data from peer
                    if (read(peerNetData) < 0) {
                        // The channel has reached end-of-stream
                    }

                    // Process incoming handshaking data
                    peerNetData.flip();
                    SSLEngineResult res = engine.unwrap(peerNetData, peerAppData);
                    peerNetData.compact();
                    handshakeStatus = res.getHandshakeStatus();

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
                    handshakeStatus = res.getHandshakeStatus();

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

    /**
     * Execute delegated tasks in the main thread. These are compute
     * intensive tasks, so there's no point in scheduling them in a different
     * thread.
     */
    private void doTasks() {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
        handshakeStatus = engine.getHandshakeStatus();
    }


}
