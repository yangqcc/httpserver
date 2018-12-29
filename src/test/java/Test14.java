/*
 * Copyright (c) 2005, 2006, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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

/**
 * @test
 * @bug 6270015
 * @summary  Light weight HTTP server
 */

import java.io.File;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.jboss.com.sun.net.httpserver.Filter;
import org.jboss.com.sun.net.httpserver.Headers;
import org.jboss.com.sun.net.httpserver.HttpContext;
import org.jboss.com.sun.net.httpserver.HttpExchange;
import org.jboss.com.sun.net.httpserver.HttpHandler;
import org.jboss.com.sun.net.httpserver.HttpServer;

/**
 * Test filters
 */

public class Test14 extends Test {

    static final String test_input = "Hello world";
    static final String test_output = "Ifmmp!xpsme";

    /* an outputstream which transforms the output data
     * by adding one to each byte
     */
    static class OffsetOutputStream extends FilterOutputStream {
        OffsetOutputStream (OutputStream os) {
            super (os);
        }
        public void write (int b) throws IOException {
            super.write (b+1);
        }
    }

    static class OffsetFilter extends Filter {
        public String description() {
            return "Translates outgoing data";
        }

        public void destroy(HttpContext c) {}
        public void init(HttpContext c) {}

        @Override
        public void doFilter (HttpExchange exchange, Filter.Chain chain)
        throws IOException {
            exchange.setStreams (null, new OffsetOutputStream(
                exchange.getResponseBody()
            ));
            chain.doFilter (exchange);
        }
    }

    public static void main (String[] args) throws Exception {
        Handler handler = new Handler();
        InetSocketAddress addr = new InetSocketAddress (0);
        HttpServer server = HttpServer.create (addr, 0);
        HttpContext ctx = server.createContext ("/test", handler);

        File logfile = new File (
            System.getProperty ("test.classes")+ "/log.txt"
        );

        ctx.getFilters().add (new OffsetFilter());
        ctx.getFilters().add (new LogFilter(logfile));
        if (ctx.getFilters().size() != 2) {
            throw new RuntimeException ("wrong filter list size");
        }
        ExecutorService executor = Executors.newCachedThreadPool();
        server.setExecutor (executor);
        server.start ();

        URL url = new URL ("http://localhost:"+server.getAddress().getPort()+"/test/foo.html");
        System.out.print ("Test14: " );
        HttpURLConnection urlc = (HttpURLConnection)url.openConnection ();
        InputStream is = urlc.getInputStream();
        int x = 0;
        String output="";
        while ((x=is.read())!= -1) {
            output = output + (char)x;
        }
        error = !output.equals (test_output);
        server.stop(2);
        executor.shutdown();
        if (error ) {
            throw new RuntimeException ("test failed error");
        }
        System.out.println ("OK");

    }

    public static boolean error = false;

    static class Handler implements HttpHandler {
        int invocation = 1;
        public void handle (HttpExchange t)
            throws IOException
        {
            InputStream is = t.getRequestBody();
            Headers map = t.getRequestHeaders();
            Headers rmap = t.getResponseHeaders();
            while (is.read () != -1) ;
            is.close();
            String response = test_input;
            t.sendResponseHeaders (200, response.length());
            OutputStream os = t.getResponseBody();
            os.write (response.getBytes());
            t.close();
        }
    }
}
