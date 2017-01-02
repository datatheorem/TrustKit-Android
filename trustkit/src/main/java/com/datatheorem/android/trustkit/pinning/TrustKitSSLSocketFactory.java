package com.datatheorem.android.trustkit.pinning;


import android.net.SSLCertificateSocketFactory;
import android.util.Log;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;


public class TrustKitSSLSocketFactory extends SSLCertificateSocketFactory {

    private SSLSocketFactory delegate;

    // TODO(ad): Figure this out
    public TrustKitSSLSocketFactory() {
        super(0);
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{TrustManagerBuilder.baselineTrustManager}, null);
            delegate = sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return new String[0];
    }
    @Override
    public String[] getSupportedCipherSuites() {
        return new String[0];
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddr, int localPort)
            throws IOException {
        // Force the use of our trust manager
        TrustManager[] pinningTrustManagers = new TrustManager[]{TrustManagerBuilder.getTrustManager(host)};
        setTrustManagers(pinningTrustManagers);
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, pinningTrustManagers, null);
            delegate = sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
        // Try to create the socket, which will trigger the SSL handshake
        return super.createSocket(host, port, localAddr, localPort);
    }

    @Override
    public Socket createSocket(Socket k, String host, int port, boolean close) throws IOException {
        // Force the use of our trust manager

        TrustManager[] pinningTrustManagers = new TrustManager[]{TrustManagerBuilder.getTrustManager(host)};
        setTrustManagers(pinningTrustManagers);
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, pinningTrustManagers, null);
            delegate = sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
        // Try to create the socket, which will trigger the SSL handshake
        return super.createSocket(k, host, port, close);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        // Force the use of our trust manager

        TrustManager[] pinningTrustManagers = new TrustManager[]{TrustManagerBuilder.getTrustManager(host)};
        setTrustManagers(pinningTrustManagers);
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, pinningTrustManagers, null);
            delegate = sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
        // Try to create the socket, which will trigger the SSL handshake
        return super.createSocket(host, port);
    }
}
