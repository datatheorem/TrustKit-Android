package com.datatheorem.android.trustkit.pinning;


import android.net.SSLCertificateSocketFactory;
import android.util.Log;

import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.config.TrustKitConfiguration;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

public class PinningSSLSocketFactory extends SSLCertificateSocketFactory {

    // TODO(ad): Figure this out
    public PinningSSLSocketFactory() {
        super(0);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddr, int localPort)
            throws IOException {
        // Force the use of our PinningTrustManager
        setTrustManagers(new TrustManager[]{createTrustManager(host, port)});

        try {
            return super.createSocket(host, port, localAddr, localPort);
        } catch (SSLPeerUnverifiedException e) {
            // Hostname validation failed
            System.out.println("Hostname validation failed");
            // TODO(ad): Send a report
            throw e;
        }
    }

    @Override
    public Socket createSocket(Socket k, String host, int port, boolean close) throws IOException {
        // Get this domain's pinning configuration if any
        TrustKitConfiguration config = TrustKit.getInstance().getConfiguration();
        // TODO(ad): Handle subdomains here
        String notedHostname = host;
        PinnedDomainConfiguration serverConfig = config.get(notedHostname);
        PinningTrustManager trustManager = null;

        // Force the use of our PinningTrustManager if the domain was pinned
        // Otherwise leave the default trust manager
        if (serverConfig != null) {
            trustManager = new PinningTrustManager(host, port, notedHostname,
                    serverConfig);
            setTrustManagers(new TrustManager[]{trustManager});
        }

        try {
            return super.createSocket(k, host, port, close);
        } catch (SSLPeerUnverifiedException e) {
            // Hostname validation failed
            if (serverConfig != null) {
                // Domain was pinned - send a pin failure report
                System.out.println("Hostname validation failed");
                TrustKit.getInstance().getReporter().pinValidationFailed(host, port,
                        trustManager.getServerVerifiedChain(), notedHostname, serverConfig,
                        PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED);
            }

            throw e;
        }
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        // Get this domain's pinning configuration if any
        TrustKitConfiguration config = TrustKit.getInstance().getConfiguration();
        // TODO(ad): Handle subdomains here
        String notedHostname = host;
        PinnedDomainConfiguration hostConfig = config.get(notedHostname);

        // Force the use of our PinningTrustManager
        setTrustManagers(new TrustManager[]{
                new PinningTrustManager(host, port, notedHostname, hostConfig)
        });

        try {
            return super.createSocket(host, port);
        } catch (SSLPeerUnverifiedException e) {
            // Hostname validation failed
            System.out.println("Hostname validation failed");

            // Send a pin failure report
            //X509Certificate[] chain = socket.getSession().getPeerCertificateChain();
            //TrustKit.getInstance().getReporter().pinValidationFailed(host, port, chain,
            //        notedHostname, hostConfig,
            //        PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED);

            // Then re-throw the exception to close the SSL connection
            throw e;
        }
    }

    private static TrustManager createTrustManager(String host, int port) {
        // Get this domain's pinning configuration if any
        TrustKitConfiguration config = TrustKit.getInstance().getConfiguration();
        String notedHostname = host;
        PinnedDomainConfiguration hostConfig = config.get(notedHostname);
        return new PinningTrustManager(host, port, notedHostname, hostConfig);
    }
}
