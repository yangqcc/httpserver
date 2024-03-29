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

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * encapsulates all the connection specific state for a HTTP/S connection
 * one of these is hung from the selector attachment and is used to locate
 * everything from that.
 */
class HttpConnection {

    private HttpContextImpl context;
    private SSLEngine engine;
    private SSLContext sslContext;
    SSLStreams sslStreams;

    /**
     * high level streams returned to application
     */
    private InputStream inputStream;

    /**
     * low level stream that sits directly over channel
     */
    InputStream rawIn;
    OutputStream rawOut;

    private SocketChannel chan;
    SelectionKey selectionKey;
    private String protocol;
    long time;
    // time this connection was created
    volatile long creationTime;
    // time we started writing the response
    volatile long rspStartedTime;
    private int remaining;
    boolean closed = false;
    private Logger logger;

    public enum State {IDLE, REQUEST, RESPONSE}

    ;
    volatile State state;
    private final Map<String, Object> attributes = new HashMap<String, Object>();
    private final ServerImpl server;

    @Override
    public String toString() {
        String s = null;
        if (chan != null) {
            s = chan.toString();
        }
        return s;
    }

    HttpConnection(ServerImpl server) {
        this.server = server;
    }

    void setChannel(SocketChannel c) {
        chan = c;
    }

    void setContext(HttpContextImpl ctx) {
        context = ctx;
    }

    State getState() {
        return state;
    }

    void setState(State s) {
        state = s;
    }

    void setParameters(
            InputStream in, OutputStream rawout, SocketChannel chan,
            SSLEngine engine, SSLStreams sslStreams, SSLContext sslContext, String protocol,
            HttpContextImpl context, InputStream raw
    ) {
        this.context = context;
        this.inputStream = in;
        this.rawOut = rawout;
        this.rawIn = raw;
        this.protocol = protocol;
        this.engine = engine;
        this.chan = chan;
        this.sslContext = sslContext;
        this.sslStreams = sslStreams;
        this.logger = context.getLogger();
    }

    SocketChannel getChannel() {
        return chan;
    }

    synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        if (logger != null && chan != null) {
            logger.finest("Closing connection: " + chan.toString());
        }

        if (!chan.isOpen()) {
            server.dPrint("Channel already closed");
            return;
        }
        try {
            /* need to ensure temporary selectors are closed */
            if (rawIn != null) {
                rawIn.close();
            }
        } catch (IOException e) {
            server.dPrint(e);
        }
        try {
            if (rawOut != null) {
                rawOut.close();
            }
        } catch (IOException e) {
            server.dPrint(e);
        }
        try {
            if (sslStreams != null) {
                sslStreams.close();
            }
        } catch (IOException e) {
            server.dPrint(e);
        }
        try {
            chan.close();
        } catch (IOException e) {
            server.dPrint(e);
        }
    }

    /**
     * remaining is the number of bytes left on the lowest level inputstream
     * after the exchange is finished
     */
    void setRemaining(int r) {
        remaining = r;
    }

    int getRemaining() {
        return remaining;
    }

    SelectionKey getSelectionKey() {
        return selectionKey;
    }

    InputStream getInputStream() {
        return inputStream;
    }

    OutputStream getRawOutputStream() {
        return rawOut;
    }

    String getProtocol() {
        return protocol;
    }

    SSLEngine getSSLEngine() {
        return engine;
    }

    SSLContext getSSLContext() {
        return sslContext;
    }

    HttpContextImpl getHttpContext() {
        return context;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

}
