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
            // Hostname validation failed
            if (serverConfig != null) {
                // If the domain was pinned, send a pin failure report
                System.out.println("Hostname validation failed");
                TrustKit.getInstance().getReporter().pinValidationFailed(host, port,
                        trustManager.getServerVerifiedChain(), notedHostname, serverConfig,
                        PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED);

                // TOOD(ad): Send a broadcast notification
            }

            // Forward the exception
            throw e;
        } catch (SSLHandshakeException e) {
            // Path validation or pinning validation failed
            if (serverConfig != null) {
                // If the domain was pinned, send a pin failure report
                // The validation result and chain are available in the trust manager
                PinValidationResult validationResult = trustManager.getServerChainValidationResult();
                Certificate[] serverChainToSend = trustManager.getServerReceivedChain();
                if (validationResult == PinValidationResult.FAILED) {
                    // If path validation succeeded (but not pinning), we can get the verified chain
                    serverChainToSend = trustManager.getServerVerifiedChain();
                }

                // Send a pin failure report
                TrustKit.getInstance().getReporter().pinValidationFailed(host, port,
                        serverChainToSend, notedHostname, serverConfig, validationResult);

                // TOOD(ad): Send a broadcast notification
            }

            // Forward the exception
            throw e;
        }

        // If we get here, validation succeeded
        // TOOD(ad): Send a broadcast notification
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
            // Hostname validation failed
            if (serverConfig != null) {
                // If the domain was pinned, send a pin failure report
                System.out.println("Hostname validation failed");
                TrustKit.getInstance().getReporter().pinValidationFailed(host, port,
                        trustManager.getServerVerifiedChain(), notedHostname, serverConfig,
                        PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED);

                // TOOD(ad): Send a broadcast notification
            }

            // Forward the exception
            throw e;
        } catch (SSLHandshakeException e) {
            // Path validation or pinning validation failed
            if (serverConfig != null) {
                // If the domain was pinned, send a pin failure report
                // The validation result and chain are available in the trust manager
                PinValidationResult validationResult = trustManager.getServerChainValidationResult();
                Certificate[] serverChainToSend = trustManager.getServerReceivedChain();
                if (validationResult == PinValidationResult.FAILED) {
                    // If path validation succeeded (but not pinning), we can get the verified chain
                    serverChainToSend = trustManager.getServerVerifiedChain();
                }

                // Send a pin failure report
                TrustKit.getInstance().getReporter().pinValidationFailed(host, port,
                        serverChainToSend, notedHostname, serverConfig, validationResult);

                // TOOD(ad): Send a broadcast notification
            }

            // Forward the exception
            throw e;
        }

        // If we get here, validation succeeded
        // TOOD(ad): Send a broadcast notification
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
            // Hostname validation failed
            if (serverConfig != null) {
                // If the domain was pinned, send a pin failure report
                System.out.println("Hostname validation failed");
                TrustKit.getInstance().getReporter().pinValidationFailed(host, port,
                        trustManager.getServerVerifiedChain(), notedHostname, serverConfig,
                        PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED);

                // TOOD(ad): Send a broadcast notification
            }

            // Forward the exception
            throw e;
        } catch (SSLHandshakeException e) {
            // Path validation or pinning validation failed
            if (serverConfig != null) {
                // If the domain was pinned, send a pin failure report
                // The validation result and chain are available in the trust manager
                PinValidationResult validationResult = trustManager.getServerChainValidationResult();
                Certificate[] serverChainToSend = trustManager.getServerReceivedChain();
                if (validationResult == PinValidationResult.FAILED) {
                    // If path validation succeeded (but not pinning), we can get the verified chain
                    serverChainToSend = trustManager.getServerVerifiedChain();
                }

                // Send a pin failure report
                TrustKit.getInstance().getReporter().pinValidationFailed(host, port,
                        serverChainToSend, notedHostname, serverConfig, validationResult);

                // TOOD(ad): Send a broadcast notification
            }

            // Forward the exception
            throw e;
        }

        // If we get here, validation succeeded
        // TOOD(ad): Send a broadcast notification
    }
}
