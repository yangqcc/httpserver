/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.jboss.sun.net.httpserver;

import org.jboss.com.sun.net.httpserver.HttpsConfigurator;
import org.jboss.com.sun.net.httpserver.HttpsParameters;

import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * given a non-blocking SocketChannel, it produces
 * (blocking) streams which encrypt/decrypt the SSL content
 * and handle the SSL handshaking automatically.
 */
class SSLStreams {

    private SSLContext sslctx;
    private SocketChannel socketChannel;
    private SSLEngine engine;
    private EngineWrapper wrapper;
    private OutputStream os;
    InputStream is;
    ServerImpl server;

    /**
     * held by thread doing the hand-shake on this connection
     */
    private Lock handshaking = new ReentrantLock();

    SSLStreams(ServerImpl server, SSLContext sslCtx, SocketChannel socketChannel) {
        this.server = server;
        this.sslctx = sslCtx;
        this.socketChannel = socketChannel;
        InetSocketAddress addr = (InetSocketAddress) socketChannel.socket().getRemoteSocketAddress();
        // This is the server side of the connection so we do not need to hint as to the clients address.
        engine = sslCtx.createSSLEngine();
        engine.setUseClientMode(false);
        HttpsConfigurator cfg = server.getHttpsConfigurator();
        configureEngine(cfg, addr);
        wrapper = new EngineWrapper(socketChannel, engine);
    }

    private void configureEngine(HttpsConfigurator cfg, InetSocketAddress addr) {
        if (cfg != null) {
            Parameters params = new Parameters(cfg, addr);
            //BEGIN_TIGER_EXCLUDE
            cfg.configure(params);
            SSLParameters sslParams = params.getSSLParameters();
            if (sslParams != null) {
                engine.setSSLParameters(sslParams);
            }
            //END_TIGER_EXCLUDE
            else {
                /* tiger compatibility */
                if (params.getCipherSuites() != null) {
                    try {
                        engine.setEnabledCipherSuites(params.getCipherSuites());
                    } catch (IllegalArgumentException e) { /* LOG */}
                }
                if (params.getNeedClientAuth()) {
                    engine.setNeedClientAuth(true);
                }
                if (params.getWantClientAuth()) {
                    engine.setWantClientAuth(true);
                }
                if (params.getProtocols() != null) {
                    try {
                        engine.setEnabledProtocols(params.getProtocols());
                    } catch (IllegalArgumentException e) { /* LOG */}
                }
            }
        }
    }

    class Parameters extends HttpsParameters {
        InetSocketAddress addr;
        HttpsConfigurator cfg;

        Parameters(HttpsConfigurator cfg, InetSocketAddress addr) {
            this.addr = addr;
            this.cfg = cfg;
        }

        @Override
        public InetSocketAddress getClientAddress() {
            return addr;
        }

        @Override
        public HttpsConfigurator getHttpsConfigurator() {
            return cfg;
        }

        //BEGIN_TIGER_EXCLUDE
        SSLParameters params;

        @Override
        public void setSSLParameters(SSLParameters p) {
            params = p;
        }

        SSLParameters getSSLParameters() {
            return params;
        }
        //END_TIGER_EXCLUDE
    }

    /**
     * cleanup resources allocated inside this object
     */
    void close() throws IOException {
        wrapper.close();
    }

    /**
     * return the SSL InputStream
     */
    InputStream getInputStream() throws IOException {
        if (is == null) {
            is = new InputStream();
        }
        return is;
    }

    /**
     * return the SSL OutputStream
     */
    OutputStream getOutputStream() throws IOException {
        if (os == null) {
            os = new OutputStream();
        }
        return os;
    }

    SSLEngine getSSLEngine() {
        return engine;
    }

    /**
     * request the engine to repeat the handshake on this session
     * the handshake must be driven by reads/writes on the streams
     * Normally, not necessary to call this.
     */
    void beginHandshake() throws SSLException {
        engine.beginHandshake();
    }

    class WrapperResult {
        SSLEngineResult result;

        /**
         * if passed in buffer was not big enough then the
         * a reallocated buffer is returned here
         */
        ByteBuffer buf;
    }

    private int appBufSize;
    private int packetBufSize;

    enum BufType {
        /**
         * 网络包
         */
        PACKET, APPLICATION
    }

    private ByteBuffer allocate(BufType type) {
        return allocate(type, -1);
    }

    private ByteBuffer allocate(BufType type, int len) {
        //DISABLED assert engine != null;
        synchronized (this) {
            int size;
            if (type == BufType.PACKET) {
                if (packetBufSize == 0) {
                    SSLSession sess = engine.getSession();
                    packetBufSize = sess.getPacketBufferSize();
                }
                if (len > packetBufSize) {
                    packetBufSize = len;
                }
                size = packetBufSize;
            } else {
                if (appBufSize == 0) {
                    SSLSession sess = engine.getSession();
                    appBufSize = sess.getApplicationBufferSize();
                }
                if (len > appBufSize) {
                    appBufSize = len;
                }
                size = appBufSize;
            }
            return ByteBuffer.allocate(size);
        }
    }

    /**
     * reallocates the buffer by :-
     * 1. creating a new buffer double the size of the old one
     * 2. putting the contents of the old buffer into the new one
     * 3. set xx_buf_size to the new size if it was smaller than new size
     * <p>
     * flip is set to true if the old buffer needs to be flipped
     * before it is copied.
     */
    private ByteBuffer realloc(ByteBuffer b, boolean flip, BufType type) {
        synchronized (this) {
            int nSize = 2 * b.capacity();
            ByteBuffer n = allocate(type, nSize);
            if (flip) {
                b.flip();
            }
            n.put(b);
            b = n;
        }
        return b;
    }

    /**
     * This is a thin wrapper over SSLEngine and the SocketChannel,
     * which guarantees the ordering of wraps/unwraps with respect to the underlying
     * channel read/writes. It handles the UNDER/OVERFLOW status codes
     * It does not handle the handshaking status codes, or the CLOSED status code
     * though once the engine is closed, any attempt to read/write to it
     * will get an exception.  The overall result is returned.
     * It functions synchronously/blocking
     */
    class EngineWrapper {

        SocketChannel socketChannel;
        SSLEngine engine;
        final Object wrapLock, unwrapLock;
        ByteBuffer unwrapSrc, wrapDst;
        boolean closed = false;
        /**
         * the number of bytes left in unwrapSrc after an unwrap()
         */
        int uRemaining;

        EngineWrapper(SocketChannel socketChannel, SSLEngine engine) {
            this.socketChannel = socketChannel;
            this.engine = engine;
            wrapLock = new Object();
            unwrapLock = new Object();
            unwrapSrc = allocate(BufType.PACKET);
            wrapDst = allocate(BufType.PACKET);
        }

        void close() {
        }

        /**
         * try to wrap and send the data in src. Handles OVERFLOW.
         * Might block if there is an outbound blockage or if another
         * thread is calling wrap(). Also, might not send any data
         * if an unwrap is needed.
         */
        WrapperResult wrapAndSend(ByteBuffer src) throws IOException {
            return wrapAndSendX(src, false);
        }

        WrapperResult wrapAndSendX(ByteBuffer src, boolean ignoreClose) throws IOException {
            if (closed && !ignoreClose) {
                throw new IOException("Engine is closed");
            }
            Status status;
            WrapperResult r = new WrapperResult();
            synchronized (wrapLock) {
                wrapDst.clear();
                do {
                    r.result = engine.wrap(src, wrapDst);
                    status = r.result.getStatus();
                    if (status == Status.BUFFER_OVERFLOW) {
                        wrapDst = realloc(wrapDst, true, BufType.PACKET);
                    }
                } while (status == Status.BUFFER_OVERFLOW);
                if (status == Status.CLOSED && !ignoreClose) {
                    closed = true;
                    return r;
                }
                if (r.result.bytesProduced() > 0) {
                    wrapDst.flip();
                    int l = wrapDst.remaining();
                    //DISABLED assert l == r.result.bytesProduced();
                    while (l > 0) {
                        l -= socketChannel.write(wrapDst);
                    }
                }
            }
            return r;
        }

        /**
         * block until a complete message is available and return it
         * in dst, together with the Result. dst may have been re-allocated
         * so caller should check the returned value in Result
         * If handshaking is in progress then, possibly no data is returned
         */
        WrapperResult recvAndUnwrap(ByteBuffer dst) throws IOException {
            Status status = Status.OK;
            WrapperResult r = new WrapperResult();
            r.buf = dst;
            if (closed) {
                throw new IOException("Engine is closed");
            }
            boolean needData;
            if (uRemaining > 0) {
                unwrapSrc.compact();
                unwrapSrc.flip();
                needData = false;
            } else {
                unwrapSrc.clear();
                needData = true;
            }
            synchronized (unwrapLock) {
                int x;
                do {
                    if (needData) {
                        do {
                            x = socketChannel.read(unwrapSrc);
                        } while (x == 0);
                        if (x == -1) {
                            throw new IOException("connection closed for reading");
                        }
                        unwrapSrc.flip();
                    }
                    r.result = engine.unwrap(unwrapSrc, r.buf);
                    status = r.result.getStatus();
                    if (status == Status.BUFFER_UNDERFLOW) {
                        if (unwrapSrc.limit() == unwrapSrc.capacity()) {
                            /* buffer not big enough */
                            unwrapSrc = realloc(unwrapSrc, false, BufType.PACKET
                            );
                        } else {
                            /* Buffer not full, just need to read more
                             * data off the channel. Reset pointers
                             * for reading off SocketChannel
                             */
                            unwrapSrc.position(unwrapSrc.limit());
                            unwrapSrc.limit(unwrapSrc.capacity());
                        }
                        needData = true;
                    } else if (status == Status.BUFFER_OVERFLOW) {
                        r.buf = realloc(r.buf, true, BufType.APPLICATION);
                        needData = false;
                    } else if (status == Status.CLOSED) {
                        closed = true;
                        r.buf.flip();
                        return r;
                    }
                } while (status != Status.OK);
            }
            uRemaining = unwrapSrc.remaining();
            return r;
        }
    }

    /**
     * send the data in the given ByteBuffer. If a handshake is needed
     * then this is handled within this method. When this call returns,
     * all of the given user data has been sent and any handshake has been
     * completed. Caller should check if engine has been closed.
     */
    public WrapperResult sendData(ByteBuffer src) throws IOException {
        WrapperResult r = null;
        while (src.remaining() > 0) {
            r = wrapper.wrapAndSend(src);
            Status status = r.result.getStatus();
            if (status == Status.CLOSED) {
                doClosure();
                return r;
            }
            HandshakeStatus hs_status = r.result.getHandshakeStatus();
            if (hs_status != HandshakeStatus.FINISHED &&
                    hs_status != HandshakeStatus.NOT_HANDSHAKING) {
                doHandshake(hs_status);
            }
        }
        return r;
    }

    /**
     * read data thru the engine into the given ByteBuffer. If the
     * given buffer was not large enough, a new one is allocated
     * and returned. This call handles handshaking automatically.
     * Caller should check if engine has been closed.
     */
    public WrapperResult recvData(ByteBuffer dst) throws IOException {
        /* we wait until some user data arrives */
        WrapperResult wrapperResult = null;
        //DISABLED assert dst.position() == 0;
        while (dst.position() == 0) {
            wrapperResult = wrapper.recvAndUnwrap(dst);
            dst = (wrapperResult.buf != dst) ? wrapperResult.buf : dst;
            Status status = wrapperResult.result.getStatus();
            if (status == Status.CLOSED) {
                doClosure();
                return wrapperResult;
            }

            HandshakeStatus hsStatus = wrapperResult.result.getHandshakeStatus();
            if (hsStatus != HandshakeStatus.FINISHED && hsStatus != HandshakeStatus.NOT_HANDSHAKING) {
                doHandshake(hsStatus);
            }
        }
        dst.flip();
        return wrapperResult;
    }

    /**
     * we've received a close notify. Need to call wrap to send
     * the response
     */
    private void doClosure() throws IOException {
        try {
            handshaking.lock();
            ByteBuffer tmp = allocate(BufType.APPLICATION);
            WrapperResult r;
            do {
                tmp.clear();
                tmp.flip();
                r = wrapper.wrapAndSendX(tmp, true);
            } while (r.result.getStatus() != Status.CLOSED);
        } finally {
            handshaking.unlock();
        }
    }

    /**
     * do the (complete) handshake after acquiring the handshake lock.
     * If two threads call this at the same time, then we depend
     * on the wrapper methods being idempotent. eg. if wrapAndSend()
     * is called with no data to send then there must be no problem
     */
    private void doHandshake(HandshakeStatus handshakeStatus) throws IOException {
        try {
            handshaking.lock();
            ByteBuffer tmp = allocate(BufType.APPLICATION);
            while (handshakeStatus != HandshakeStatus.FINISHED &&
                    handshakeStatus != HandshakeStatus.NOT_HANDSHAKING) {
                WrapperResult r = null;
                switch (handshakeStatus) {
                    case NEED_TASK:
                        Runnable task;
                        while ((task = engine.getDelegatedTask()) != null) {
                            /* run in current thread, because we are already
                             * running an external Executor
                             */
                            task.run();
                        }
                        /* fall thru - call wrap again */
                    case NEED_WRAP:
                        tmp.clear();
                        tmp.flip();
                        r = wrapper.wrapAndSend(tmp);
                        break;

                    case NEED_UNWRAP:
                        tmp.clear();
                        r = wrapper.recvAndUnwrap(tmp);
                        if (r.buf != tmp) {
                            tmp = r.buf;
                        }
                        //DISABLED assert tmp.position() == 0;
                        break;
                    default:
                        break;
                }
                handshakeStatus = r.result.getHandshakeStatus();
            }
        } finally {
            handshaking.unlock();
        }
    }

    /**
     * represents an SSL input stream. Multiple https requests can
     * be sent over one stream. closing this stream causes an SSL close
     * input.
     */
    class InputStream extends java.io.InputStream {

        ByteBuffer buf;
        boolean closed = false;

        /**
         * this stream eof
         */
        boolean eof = false;

        boolean needData = true;

        InputStream() {
            buf = allocate(BufType.APPLICATION);
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            if (closed) {
                throw new IOException("SSL stream is closed");
            }
            if (eof) {
                return -1;
            }
            int available = 0;
            if (!needData) {
                available = this.buf.remaining();
                needData = (available == 0);
            }
            if (needData) {
                this.buf.clear();
                WrapperResult r = recvData(this.buf);
                this.buf = r.buf == this.buf ? this.buf : r.buf;
                if ((available = this.buf.remaining()) == 0) {
                    eof = true;
                    return -1;
                } else {
                    needData = false;
                }
            }
            /* copy as much as possible from buf into users buf */
            if (len > available) {
                len = available;
            }
            this.buf.get(buf, off, len);
            return len;
        }

        @Override
        public int available() {
            return buf.remaining();
        }

        @Override
        public boolean markSupported() {
            /* not possible with SSLEngine */
            return false;
        }

        @Override
        public void reset() throws IOException {
            throw new IOException("mark/reset not supported");
        }

        @Override
        public long skip(long s) throws IOException {
            int n = (int) s;
            if (closed) {
                throw new IOException("SSL stream is closed");
            }
            if (eof) {
                return -1;
            }
            int ret = n;
            while (n > 0) {
                if (buf.remaining() >= n) {
                    buf.position(buf.position() + n);
                    return ret;
                } else {
                    n -= buf.remaining();
                    buf.clear();
                    WrapperResult r = recvData(buf);
                    buf = r.buf;
                }
            }
            /* not reached */
            return ret;
        }

        /**
         * close the SSL connection. All data must have been consumed
         * before this is called. Otherwise an exception will be thrown.
         * [Note. May need to revisit this. not quite the normal close() symantics
         */
        @Override
        public void close() throws IOException {
            eof = true;
            engine.closeInbound();
        }

        @Override
        public int read(byte[] buf) throws IOException {
            return read(buf, 0, buf.length);
        }

        byte[] single = new byte[1];

        @Override
        public int read() throws IOException {
            int n = read(single, 0, 1);
            if (n == 0 || n == -1) {
                return -1;
            } else {
                return single[0] & 0xFF;
            }
        }
    }

    /**
     * represents an SSL output stream. plain text data written to this stream
     * is encrypted by the stream. Multiple HTTPS responses can be sent on
     * one stream. closing this stream initiates an SSL closure
     */
    class OutputStream extends java.io.OutputStream {
        ByteBuffer buf;
        boolean closed = false;
        byte[] single = new byte[1];

        OutputStream() {
            buf = allocate(BufType.APPLICATION);
        }

        @Override
        public void write(int b) throws IOException {
            single[0] = (byte) b;
            write(single, 0, 1);
        }

        @Override
        public void write(byte[] b) throws IOException {
            write(b, 0, b.length);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (closed) {
                throw new IOException("output stream is closed");
            }
            while (len > 0) {
                int l = len > buf.capacity() ? buf.capacity() : len;
                buf.clear();
                buf.put(b, off, l);
                len -= l;
                off += l;
                buf.flip();
                WrapperResult r = sendData(buf);
                if (r.result.getStatus() == Status.CLOSED) {
                    closed = true;
                    if (len > 0) {
                        throw new IOException("output stream is closed");
                    }
                }
            }
        }

        @Override
        public void flush() {
            /* no-op */
        }

        @Override
        public void close() throws IOException {
            WrapperResult r;
            engine.closeOutbound();
            closed = true;
            HandshakeStatus stat = HandshakeStatus.NEED_WRAP;
            buf.clear();
            while (stat == HandshakeStatus.NEED_WRAP) {
                r = wrapper.wrapAndSend(buf);
                stat = r.result.getHandshakeStatus();
            }
            //DISABLED assert r.result.getStatus() == Status.CLOSED;
        }
    }
}
