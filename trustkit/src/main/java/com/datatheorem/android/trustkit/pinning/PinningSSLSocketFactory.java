package com.datatheorem.android.trustkit.pinning;


import android.net.SSLCertificateSocketFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.ssl.TrustManager;

public class PinningSSLSocketFactory extends SSLCertificateSocketFactory {

    // TODO(ad): Figure this out
    public PinningSSLSocketFactory() {
        super(0);

    }

    //@Override
    //public Socket createSocket(String host, int port, InetAddress localAddr, int localPort)
    //        throws IOException {
     //   return super.createSocket(host, port, localAddr, localPort);
        //return socket;
        // TODO(ad): Get pinnedConfiguration for this host
        // Force the use of our PinningTrustManager
        //setTrustManagers(new TrustManager[]{new PinningTrustManager(host, port, null, null)});
   // }

//    @Override
//    public static void verifyHostname(Socket socket, String hostname) throws IOException {
        // TODO(ad): Send a report if hostname validation failed
//        SSLCertificateSocketFactory.verifyHostname(socket, hostname);
//    }

}
