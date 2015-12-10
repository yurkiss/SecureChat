package ua.softserve.chat.server.nio;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.logging.Logger;

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

    private final ByteBuffer dummy;

    private boolean handshaking;
    private SSLEngineResult.HandshakeStatus handshakeStatus;

    private static final Logger LOG = Logger.getLogger(SSLChannelSession.class.getName());

    public SSLChannelSession(SocketChannel channel, SSLContext sslContext) {
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

        dummy = ByteBuffer.allocate(0);

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

    public int readRaw(ByteBuffer byteBuffer) throws IOException {
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

    public int writeRaw(ByteBuffer byteBuffer) throws IOException {
        int bytesWritten = socketChannel.write(byteBuffer);
        int totalBytesWritten = bytesWritten;

        while (bytesWritten > 0 && byteBuffer.hasRemaining()) {
            bytesWritten = socketChannel.write(byteBuffer);
            totalBytesWritten += bytesWritten;
        }

        return totalBytesWritten;
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


    void doHandshake() throws Exception {

        // Create byte buffers to use for holding application data
        int appBufferSize = engine.getSession().getApplicationBufferSize();
        ByteBuffer myAppData = ByteBuffer.allocate(appBufferSize);
        //ByteBuffer peerAppData = ByteBuffer.allocate(appBufferSize);

        // Begin handshake
        handshaking = true;
        engine.beginHandshake();
        handshakeStatus = engine.getHandshakeStatus();

        // Process handshaking message
        while (true) {

            switch (handshakeStatus) {

                case NEED_UNWRAP:
                    // Receive handshaking data from peer
                    if (readRaw(peerNetData) < 0) {
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
                        case BUFFER_OVERFLOW:
                            LOG.info("UNWRAP: BUFFER_OVERFLOW");
                        case BUFFER_UNDERFLOW:
                            LOG.info("UNWRAP: BUFFER_UNDERFLOW");
                        case CLOSED:
                            LOG.info("UNWRAP: CLOSED");
                    }
                    break;

                case NEED_WRAP:
                    // Empty the local network packet buffer.
                    outNetData.clear();

                    // Generate handshaking data
                    res = engine.wrap(dummy, outNetData);
                    handshakeStatus = res.getHandshakeStatus();

                    // Check status
                    switch (res.getStatus()) {
                        case OK:
                            outNetData.flip();
                            // Send the handshaking data to peer
                            // IOException could be thrown if the socket is dead,
                            // needs to handle it correctly.
                            writeRaw(outNetData);
                            break;
                        case BUFFER_OVERFLOW:
                        case BUFFER_UNDERFLOW:
                        case CLOSED:
                    }
                    break;

                case NEED_TASK: // Handle blocking tasks

                    doTasks();
                    break;

                case FINISHED: // Handle finished state

                    handshaking = false;
                    return;

                case NOT_HANDSHAKING:
                    // Handle
                    return;

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

//        Executor exec = Executors.newSingleThreadExecutor();
//        Runnable task;
//        while ((task = engine.getDelegatedTask()) != null) {
//            exec.execute(task);
//        }

        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
        handshakeStatus = engine.getHandshakeStatus();
    }


}
