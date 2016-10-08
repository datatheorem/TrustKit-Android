package com.datatheorem.android.trustkit.pinning;


import android.net.SSLCertificateSocketFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import javax.net.ssl.TrustManager;


class TrustKitSSLSocketFactory extends SSLCertificateSocketFactory {

    // TODO(ad): Figure this out
    TrustKitSSLSocketFactory() {
        super(0);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddr, int localPort)
            throws IOException {
        // Force the use of our trust manager
        setTrustManagers(new TrustManager[]{TrustKitTrustManagerBuilder.getTrustManager(host)});

        // Try to create the socket, which will trigger the SSL handshake
        return super.createSocket(host, port, localAddr, localPort);
    }

    @Override
    public Socket createSocket(Socket k, String host, int port, boolean close) throws IOException {
        // Force the use of our trust manager
        setTrustManagers(new TrustManager[]{TrustKitTrustManagerBuilder.getTrustManager(host)});

        // Try to create the socket, which will trigger the SSL handshake
        return super.createSocket(k, host, port, close);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        // Force the use of our trust manager
        setTrustManagers(new TrustManager[]{TrustKitTrustManagerBuilder.getTrustManager(host)});

        // Try to create the socket, which will trigger the SSL handshake
        return super.createSocket(host, port);
    }
}
