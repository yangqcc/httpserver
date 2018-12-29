package com.yqc;/*
 * Copyright (c) 2005, Oracle and/or its affiliates. All rights reserved.
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

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class SimpleSSLContext {

    SSLContext ssl;

    public SimpleSSLContext(String dir) throws IOException {
        try {
            String file = "C:\\Users\\hanke\\my.keystore";
            char[] passphrase = "123456".toCharArray();
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(file), passphrase);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, "654321".toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ks);

            ssl = SSLContext.getInstance("TLS");
            ssl.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e.getMessage());
        } catch (KeyStoreException e) {
            throw new RuntimeException(e.getMessage());
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e.getMessage());
        } catch (CertificateException e) {
            throw new RuntimeException(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    SSLContext get() {
        return ssl;
    }
}
