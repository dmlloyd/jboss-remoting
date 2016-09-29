/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, JBoss Inc., and individual contributors as indicated
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.remoting3.remote;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import org.jboss.logging.Logger;
import org.jboss.remoting3.RemotingOptions;
import org.jboss.remoting3.spi.ConnectionHandlerFactory;
import org.xnio.Buffers;
import org.xnio.ChannelListener;
import org.xnio.IoUtils;
import org.xnio.OptionMap;
import org.xnio.Pool;
import org.xnio.Pooled;
import org.xnio.Result;
import org.xnio.XnioExecutor;
import org.xnio.channels.ConnectedStreamChannel;
import org.xnio.channels.SslChannel;
import org.xnio.sasl.SaslWrapper;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class RemoteConnection {

    static final Pooled<ByteBuffer> STARTTLS_SENTINEL = Buffers.emptyPooledByteBuffer();

    private final Pool<ByteBuffer> messageBufferPool;
    private final ConnectedStreamChannel channel;
    private final OptionMap optionMap;
    private final RemoteWriteListener writeListener = new RemoteWriteListener();
    private final Executor executor;
    private final int heartbeatInterval;
    private volatile Result<ConnectionHandlerFactory> result;
    private volatile SaslWrapper saslWrapper;
    private final RemoteConnectionProvider remoteConnectionProvider;
    private final MessageReader messageReader;

    RemoteConnection(final Pool<ByteBuffer> messageBufferPool, final ConnectedStreamChannel channel, final OptionMap optionMap, final RemoteConnectionProvider remoteConnectionProvider) {
        this.messageBufferPool = messageBufferPool;
        this.channel = channel;
        this.optionMap = optionMap;
        heartbeatInterval = optionMap.get(RemotingOptions.HEARTBEAT_INTERVAL, RemotingOptions.DEFAULT_HEARTBEAT_INTERVAL);
        this.executor = remoteConnectionProvider.getExecutor();
        this.remoteConnectionProvider = remoteConnectionProvider;
        messageReader = new MessageReader(channel, writeListener.queue);
    }

    Pooled<ByteBuffer> allocate() {
        return messageBufferPool.allocate();
    }

    void setReadListener(ChannelListener<? super ConnectedStreamChannel> listener, final boolean resume) {
        RemoteLogger.log.tracef("Setting read listener to %s", listener);
        messageReader.setReadListener(listener);
        if (listener != null && resume) {
            messageReader.resumeReads();
        }
    }

    RemoteConnectionProvider getRemoteConnectionProvider() {
        return remoteConnectionProvider;
    }

    Result<ConnectionHandlerFactory> getResult() {
        return result;
    }

    void setResult(final Result<ConnectionHandlerFactory> result) {
        this.result = result;
    }

    void handleException(IOException e) {
        handleException(e, true);
    }

    void handleException(IOException e, boolean log) {
        RemoteLogger.conn.trace("Connection error detail", e);
        if (log) {
            RemoteLogger.conn.connectionError(e);
        }
        final XnioExecutor.Key key = writeListener.heartKey;
        if (key != null) {
            key.remove();
        }
        synchronized (getLock()) {
            IoUtils.safeClose(channel);
        }
        final Result<ConnectionHandlerFactory> result = this.result;
        if (result != null) {
            result.setException(e);
            this.result = null;
        }
    }

    void send(final Pooled<ByteBuffer> pooled) {
        writeListener.send(pooled, false);
    }

    void send(final Pooled<ByteBuffer> pooled, boolean close) {
        writeListener.send(pooled, close);
    }

    void shutdownWrites() {
        writeListener.shutdownWrites();
    }

    OptionMap getOptionMap() {
        return optionMap;
    }

    ConnectedStreamChannel getChannel() {
        return channel;
    }

    ChannelListener<ConnectedStreamChannel> getWriteListener() {
        return writeListener;
    }

    public Executor getExecutor() {
        return executor;
    }

    public SslChannel getSslChannel() {
        return channel instanceof SslChannel ? (SslChannel) channel : null;
    }

    SaslWrapper getSaslWrapper() {
        return saslWrapper;
    }

    MessageReader getMessageReader() {
        return messageReader;
    }

    void setSaslWrapper(final SaslWrapper saslWrapper) {
        this.saslWrapper = saslWrapper;
    }

    void handlePreAuthCloseRequest() {
        try {
            terminateHeartbeat();
            synchronized (getLock()) {
                channel.close();
            }
        } catch (IOException e) {
            RemoteLogger.conn.debug("Error closing remoting channel", e);
        }
    }

    void sendAlive() {
        final Pooled<ByteBuffer> pooled = allocate();
        boolean ok = false;
        try {
            final ByteBuffer buffer = pooled.getResource();
            buffer.put(Protocol.CONNECTION_ALIVE);
            buffer.limit(80);
            Buffers.addRandom(buffer);
            buffer.flip();
            send(pooled);
            ok = true;
            messageReader.wakeupReads();
        } finally {
            if (! ok) pooled.free();
        }
    }

    void sendAliveResponse() {
        final Pooled<ByteBuffer> pooled = allocate();
        boolean ok = false;
        try {
            final ByteBuffer buffer = pooled.getResource();
            buffer.put(Protocol.CONNECTION_ALIVE_ACK);
            buffer.limit(80);
            Buffers.addRandom(buffer);
            buffer.flip();
            send(pooled);
            ok = true;
        } finally {
            if (! ok) pooled.free();
        }
    }

    void terminateHeartbeat() {
        final XnioExecutor.Key key = writeListener.heartKey;
        if (key != null) {
            key.remove();
        }
    }

    Object getLock() {
        return writeListener.queue;
    }

    static final int SEND_SIZE = 262144;

    final class RemoteWriteListener implements ChannelListener<ConnectedStreamChannel> {

        final Queue<Pooled<ByteBuffer>> queue = new ArrayDeque<>();
        XnioExecutor.Key heartKey;
        boolean closed;
        boolean startTls;
        // compacted on lock entry
        final ByteBuffer sendBuffer = ByteBuffer.allocateDirect(SEND_SIZE);

        RemoteWriteListener() {
        }

        public void handleEvent(final ConnectedStreamChannel channel) {
            final ByteBuffer sendBuffer = this.sendBuffer;
            final Queue<Pooled<ByteBuffer>> queue = this.queue;
            Pooled<ByteBuffer> pooled;
            synchronized (queue) {
                assert channel == getChannel();
                try {
                    for (;;) {
                        while ((pooled = queue.peek()) != null) {
                            final ByteBuffer buffer = pooled.getResource();
                            final int remaining = buffer.remaining();
                            if (remaining > 0) {
                                if (sendBuffer.remaining() > remaining + 4) {
                                    sendBuffer.putInt(remaining);
                                    sendBuffer.put(buffer);
                                    RemoteLogger.conn.tracef("Buffered message %s (via queue)", buffer);
                                    queue.poll().free();
                                } else {
                                    // we've filled as much as we can
                                    break;
                                }
                            } else {
                                if (pooled == STARTTLS_SENTINEL) {
                                    startTls = true;
                                    break;
                                } else {
                                    // otherwise skip other empty message rather than try and write it
                                    queue.poll().free();
                                }
                            }
                        }
                        if (sendBuffer.position() == 0) {
                            if (startTls) {
                                if (channel.flush()) {
                                    final SslChannel sslChannel = getSslChannel();
                                    assert sslChannel != null; // because STARTTLS would be false in this case
                                    RemoteLogger.conn.trace("Firing STARTTLS handshake");
                                    sslChannel.startHandshake();
                                    startTls = false;
                                } else {
                                    // try again later
                                    return;
                                }
                            } else {
                                // nothing to send, time to flush
                                break;
                            }
                        } else {
                            sendBuffer.flip();
                            long res;
                            try {
                                res = channel.write(sendBuffer);
                                if (res > 0 && RemoteLogger.conn.isTraceEnabled()) {
                                    RemoteLogger.conn.tracef("Flushed %d bytes", Long.valueOf(res));
                                }
                            } finally {
                                sendBuffer.compact();
                            }
                            if (res == 0) {
                                RemoteLogger.conn.trace("No bytes flushed; exiting");
                                // try again later
                                return;
                            }
                        }
                    }
                    if (channel.flush()) {
                        RemoteLogger.conn.trace("Flushed channel");
                        if (closed) {
                            terminateHeartbeat();
                            // End of queue reached; shut down and try to flush the remainder
                            channel.shutdownWrites();
                            if (channel.flush()) {
                                getMessageReader().finishedWrites();
                                RemoteLogger.conn.trace("Shut down writes on channel");
                                return;
                            }
                            // either this is successful and no more notifications will come, or not and it will be retried
                            // either way we're done here
                            return;
                        } else {
                            this.heartKey = channel.getIoThread().executeAfter(heartbeatCommand, heartbeatInterval, TimeUnit.MILLISECONDS);
                        }
                        channel.suspendWrites();
                        RemoteLogger.conn.trace("Writes suspended");
                    }
                } catch (IOException e) {
                    handleException(e, false);
                    messageReader.wakeupReads();
                    while ((pooled = queue.poll()) != null) {
                        pooled.free();
                    }
                }
                // else try again later
            }
        }

        public void shutdownWrites() {
            synchronized (queue) {
                closed = true;
                terminateHeartbeat();
                final ConnectedStreamChannel channel = getChannel();
                try {
                    if (! queue.isEmpty()) {
                        channel.resumeWrites();
                        return;
                    }
                    channel.shutdownWrites();
                    if (! channel.flush()) {
                        channel.resumeWrites();
                        return;
                    }
                    getMessageReader().finishedWrites();
                    RemoteLogger.conn.trace("Shut down writes on channel");
                } catch (IOException e) {
                    handleException(e, false);
                    messageReader.wakeupReads();
                    Pooled<ByteBuffer> unqueued;
                    while ((unqueued = queue.poll()) != null) {
                        unqueued.free();
                    }
                }
            }
        }

        public void send(final Pooled<ByteBuffer> pooled, final boolean close) {
            channel.getIoThread().execute(new Runnable() {
                @Override
                public void run() {

                    synchronized (queue) {
                        XnioExecutor.Key heartKey = RemoteWriteListener.this.heartKey;
                        if (heartKey != null) heartKey.remove();
                        if (closed) { pooled.free(); return; }
                        if (close) { closed = true; }
                        final ConnectedStreamChannel channel = getChannel();
                        boolean free = true;
                        try {
                            final SaslWrapper wrapper = saslWrapper;
                            if (wrapper != null) {
                                final ByteBuffer buffer = pooled.getResource();
                                final ByteBuffer source = buffer.duplicate();
                                buffer.clear();
                                wrapper.wrap(buffer, source);
                                buffer.flip();
                            }
                            final ByteBuffer buffer = pooled.getResource();
                            RemoteLogger.conn.tracef("Enqueued %s", buffer);
                            final boolean empty = queue.isEmpty();
                            queue.add(pooled);
                            free = false;
                            if (empty) {
                                channel.resumeWrites();
                                RemoteLogger.conn.trace("Resumed writes");
                            }
                        } catch (IOException e) {
                            handleException(e, false);
                            messageReader.wakeupReads();
                            Pooled<ByteBuffer> unqueued;
                            while ((unqueued = queue.poll()) != null) {
                                unqueued.free();
                            }
                        } finally {
                            if (free) {
                                pooled.free();
                            }
                        }
                    }
                }
            });
        }
    }

    private final Runnable heartbeatCommand = new Runnable() {
        public void run() {
            sendAlive();
        }
    };

    public String toString() {
        return String.format("Remoting connection %08x to %s of %s", Integer.valueOf(hashCode()), channel.getPeerAddress(), getRemoteConnectionProvider().getConnectionProviderContext().getEndpoint());
    }
}
