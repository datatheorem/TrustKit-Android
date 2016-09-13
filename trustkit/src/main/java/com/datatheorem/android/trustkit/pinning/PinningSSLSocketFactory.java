package com.datatheorem.android.trustkit.pinning;


import android.net.SSLCertificateSocketFactory;

import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.config.TrustKitConfiguration;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.Certificate;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManager;


public class PinningSSLSocketFactory extends SSLCertificateSocketFactory {

    // TODO(ad): Figure this out
    public PinningSSLSocketFactory() {
        super(0);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddr, int localPort)
            throws IOException {
        // Get this domain's pinning configuration if any
        TrustKitConfiguration config = TrustKit.getInstance().getConfiguration();
        // TODO(ad): Handle subdomains here
        String notedHostname = host;
        PinnedDomainConfiguration serverConfig = config.get(notedHostname);
        PinningTrustManager trustManager = null;

        // Force the use of our PinningTrustManager if the domain was pinned
        if (serverConfig != null) {
            trustManager = new PinningTrustManager(serverConfig.getPublicKeyHashes());
            setTrustManagers(new TrustManager[]{trustManager});
        }

        // Try to create the socket, which will trigger the SSL handshake
        try {
            return super.createSocket(host, port, localAddr, localPort);
        } catch (SSLPeerUnverifiedException e) {
            // Hostname validation failed - send a report if the domain is pinned
            if (serverConfig != null) {
                handlePeerUnverifiedException(trustManager, host, port, notedHostname, serverConfig);
            }
            // Forward the exception
            throw e;

        } catch (SSLHandshakeException e) {
            if (serverConfig != null) {
                // The domain was pinned - figure out why the handshake failed and send a report
                handleHandshakeException(trustManager, host, port, notedHostname, serverConfig);
            }
            // Forward the exception
            throw e;
        }
        // If we get here, validation succeeded
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
        if (serverConfig != null) {
            trustManager = new PinningTrustManager(serverConfig.getPublicKeyHashes());
            setTrustManagers(new TrustManager[]{trustManager});
        }

        // Try to create the socket, which will trigger the SSL handshake
        try {
            return super.createSocket(k, host, port, close);

        } catch (SSLPeerUnverifiedException e) {
            // Hostname validation failed - send a report if the domain is pinned
            if (serverConfig != null) {
                handlePeerUnverifiedException(trustManager, host, port, notedHostname, serverConfig);
            }
            // Forward the exception
            throw e;

        } catch (SSLHandshakeException e) {
            if (serverConfig != null) {
                // The domain was pinned - figure out why the handshake failed and send a report
                handleHandshakeException(trustManager, host, port, notedHostname, serverConfig);
            }
            // Forward the exception
            throw e;
        }
        // If we get here, validation succeeded
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        // Get this domain's pinning configuration if any
        TrustKitConfiguration config = TrustKit.getInstance().getConfiguration();
        // TODO(ad): Handle subdomains here
        String notedHostname = host;
        PinnedDomainConfiguration serverConfig = config.get(notedHostname);
        PinningTrustManager trustManager = null;

        // Force the use of our PinningTrustManager if the domain was pinned
        if (serverConfig != null) {
            trustManager = new PinningTrustManager(serverConfig.getPublicKeyHashes());
            setTrustManagers(new TrustManager[]{trustManager});
        }

        // Try to create the socket, which will trigger the SSL handshake
        try {
            return super.createSocket(host, port);
        } catch (SSLPeerUnverifiedException e) {
            // Hostname validation failed - send a report if the domain is pinned
            if (serverConfig != null) {
                handlePeerUnverifiedException(trustManager, host, port, notedHostname, serverConfig);
            }
            // Forward the exception
            throw e;

        } catch (SSLHandshakeException e) {
            if (serverConfig != null) {
                // The domain was pinned - figure out why the handshake failed and send a report
                handleHandshakeException(trustManager, host, port, notedHostname, serverConfig);
            }
            // Forward the exception
            throw e;
        }
        // If we get here, validation succeeded
    }

    private static void handlePeerUnverifiedException(PinningTrustManager trustManager,
                                                      String serverHostname,
                                                      Integer serverPort,
                                                      String notedHostname,
                                                      PinnedDomainConfiguration serverConfig) {
        // Hostname validation failed - send a pin failure report
        System.out.println("Hostname validation failed");
        TrustKit.getInstance().getReporter().pinValidationFailed(serverHostname, serverPort,
                trustManager.getServerVerifiedChain(), notedHostname, serverConfig,
                PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED);

        // TOOD(ad): Send a broadcast notification
    }

    private static void handleHandshakeException(PinningTrustManager trustManager,
                                                 String serverHostname,
                                                 Integer serverPort,
                                                 String notedHostname,
                                                 PinnedDomainConfiguration serverConfig) {
        boolean shouldSendReport = false;
        Certificate[] serverChainToSend = null;
        PinValidationResult result = trustManager.getServerChainValidationResult();

        if (result == PinValidationResult.FAILED) {
            // Path validation failed - send a report with the received chain
            serverChainToSend = trustManager.getServerReceivedChain();
            shouldSendReport = true;
            
        } else if (result == PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED) {
            // Pinning validation failed - send a report with the verified chain
            serverChainToSend = trustManager.getServerVerifiedChain();
            shouldSendReport = true;
        }

        // Send a pin failure report if path or pinning validation failed
        // Do not send a report for any other type of SSL handshake error
        if (shouldSendReport) {
            TrustKit.getInstance().getReporter().pinValidationFailed(serverHostname, serverPort,
                    serverChainToSend, notedHostname, serverConfig, result);
        }

        // TOOD(ad): Send a broadcast notification regardless of whether validation failed
    }
}

