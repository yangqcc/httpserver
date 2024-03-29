/*
 * Copyright (c) 2005, Oracle and/or its affiliates. All rights reserved.
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

import org.jboss.com.sun.net.httpserver.HttpContext;
import org.jboss.com.sun.net.httpserver.HttpHandler;
import org.jboss.com.sun.net.httpserver.HttpsConfigurator;
import org.jboss.com.sun.net.httpserver.HttpsServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.Executor;

/**
 * @author yangqc
 */
public class HttpsServerImpl extends HttpsServer {

    ServerImpl server;

    HttpsServerImpl() throws IOException {
        this(new InetSocketAddress(443), 0);
    }

    HttpsServerImpl(
            InetSocketAddress addr, int backlog
    ) throws IOException {
        this(addr, backlog, null);
    }

    HttpsServerImpl(InetSocketAddress addr, int backlog, Map<String, String> configuration) throws IOException {
        server = new ServerImpl(this, "https", addr, backlog, configuration);
    }

    @Override
    public void setHttpsConfigurator(HttpsConfigurator config) {
        server.setHttpsConfigurator(config);
    }

    @Override
    public HttpsConfigurator getHttpsConfigurator() {
        return server.getHttpsConfigurator();
    }

    @Override
    public void bind(InetSocketAddress addr, int backlog) throws IOException {
        server.bind(addr, backlog);
    }

    @Override
    public void start() {
        server.start();
    }

    @Override
    public void setExecutor(Executor executor) {
        server.setExecutor(executor);
    }

    @Override
    public Executor getExecutor() {
        return server.getExecutor();
    }

    @Override
    public void stop(int delay) {
        server.stop(delay);
    }

    @Override
    public HttpContextImpl createContext(String path, HttpHandler handler) {
        return server.createContext(path, handler);
    }

    @Override
    public HttpContextImpl createContext(String path) {
        return server.createContext(path);
    }

    @Override
    public void removeContext(String path) throws IllegalArgumentException {
        server.removeContext(path);
    }

    @Override
    public void removeContext(HttpContext context) throws IllegalArgumentException {
        server.removeContext(context);
    }

    @Override
    public InetSocketAddress getAddress() {
        return server.getAddress();
    }
}
