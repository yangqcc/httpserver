package com.yqc;

import org.jboss.com.sun.net.httpserver.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;

public class TestHttpsServer {

    public static boolean error = false;
    final static int SIZE = 999999;

    static class Handler implements HttpHandler {
        int invocation = 1;

        @Override
        public void handle(HttpExchange t) throws IOException {
            InputStream is = t.getRequestBody();
            Headers map = t.getRequestHeaders();
            Headers rmap = t.getResponseHeaders();
            int c, count = 0;
            while ((c = is.read()) != -1) {
                if (c != (count % 100)) {
                    error = true;
                    break;
                }
                count++;
            }
            if (count != SIZE) {
                error = true;
            }
            is.close();
            byte[] bytes = "hello".getBytes();
            t.sendResponseHeaders(200, bytes.length);
            t.getResponseBody().write(bytes);
            t.close();
        }
    }


    public static void main(String[] args) throws IOException {
        HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress("localhost", 80), 100);
        HttpsConfigurator httpsConfigurator = new HttpsConfigurator(new SimpleSSLContext(null).get());
        httpsServer.setHttpsConfigurator(httpsConfigurator);
        httpsServer.createContext("/test", new Handler());
        httpsServer.start();
    }
}
