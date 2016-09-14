package com.datatheorem.android.trustkit.pinning;


import android.net.SSLCertificateSocketFactory;
import android.util.Base64;

import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.config.TrustKitConfiguration;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

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
        CertificateChainCaptorTrustManager trustManager = null;

        // Force the use of our CertificateChainCaptorTrustManager if the domain was pinned
        if (serverConfig != null) {
            trustManager = new CertificateChainCaptorTrustManager();
            setTrustManagers(new TrustManager[]{trustManager});
        }

        // Try to create the socket, which will trigger the SSL handshake
        IOException handshakeError = null;
        Socket socket = null;

        // Try to create the socket, which will trigger the SSL handshake
        try {
            socket = super.createSocket(host, port, localAddr, localPort);
        } catch (SSLPeerUnverifiedException | SSLHandshakeException e) {
            // Most likely a certificate validation error
            handshakeError = e;
        }

        // If the domain is not pinned, do not do pinning validation and do not send reports
        if (serverConfig == null) {
            if (handshakeError != null) {
                throw handshakeError;
            } else {
                return socket;
            }
        }

        // The domain is pinned - also do pinning validation and send a report if needed
        performPinningValidationAndSendReport(host, port, trustManager, handshakeError,
                notedHostname, serverConfig);

        // All done - if we get here, validation succeeded
        return socket;
    }

    @Override
    public Socket createSocket(Socket k, String host, int port, boolean close) throws IOException {
        // Get this domain's pinning configuration if any
        TrustKitConfiguration config = TrustKit.getInstance().getConfiguration();
        // TODO(ad): Handle subdomains here
        String notedHostname = host;
        PinnedDomainConfiguration serverConfig = config.get(notedHostname);
        CertificateChainCaptorTrustManager trustManager = null;

        // Force the use of our CertificateChainCaptorTrustManager if the domain was pinned
        if (serverConfig != null) {
            trustManager = new CertificateChainCaptorTrustManager();
            setTrustManagers(new TrustManager[]{trustManager});
        }

        // Try to create the socket, which will trigger the SSL handshake
        IOException handshakeError = null;
        Socket socket = null;

        // Try to create the socket, which will trigger the SSL handshake
        try {
            socket = super.createSocket(k, host, port, close);
        } catch (SSLPeerUnverifiedException | SSLHandshakeException e) {
            // Most likely a certificate validation error
            handshakeError = e;
        }

        // If the domain is not pinned, do not do pinning validation and do not send reports
        if (serverConfig == null) {
            if (handshakeError != null) {
                throw handshakeError;
            }
            else {
                return socket;
            }
        }

        // The domain is pinned - also do pinning validation and send a report if needed
        performPinningValidationAndSendReport(host, port, trustManager, handshakeError,
                notedHostname, serverConfig);

        // All done - if we get here, validation succeeded
        return socket;
    }


    @Override
    public Socket createSocket(String host, int port) throws IOException {
        // Get this domain's pinning configuration if any
        TrustKitConfiguration config = TrustKit.getInstance().getConfiguration();
        // TODO(ad): Handle subdomains here
        String notedHostname = host;
        PinnedDomainConfiguration serverConfig = config.get(notedHostname);
        CertificateChainCaptorTrustManager trustManager = null;

        // Force the use of our CertificateChainCaptorTrustManager if the domain was pinned
        if (serverConfig != null) {
            trustManager = new CertificateChainCaptorTrustManager();
            setTrustManagers(new TrustManager[]{trustManager});
        }

        // Try to create the socket, which will trigger the SSL handshake
        IOException handshakeError = null;
        Socket socket = null;
        try {
            socket = super.createSocket(host, port);
        } catch (SSLPeerUnverifiedException | SSLHandshakeException e) {
            // Most likely a certificate validation error
            handshakeError = e;
        }

        // If the domain is not pinned, do not do pinning validation and do not send reports
        if (serverConfig == null) {
            if (handshakeError != null) {
                throw handshakeError;
            }
            else {
                return socket;
            }
        }

        // The domain is pinned - also do pinning validation and send a report if needed
        performPinningValidationAndSendReport(host, port, trustManager, handshakeError,
                notedHostname, serverConfig);

        // All done - if we get here, validation succeeded
        return socket;
    }

    private static void performPinningValidationAndSendReport(String serverHostname,
                                                              int serverPort,
                                                              CertificateChainCaptorTrustManager trustManager,
                                                              IOException handshakeError,
                                                              String notedHostname,
                                                              PinnedDomainConfiguration serverConfig) throws IOException {

        List<Certificate> serverChainToSend = null;
        PinValidationResult certificateValidationResult =
                PinValidationResult.ERROR_INVALID_PARAMETERS;
        boolean shouldSendReport = false;

        // If the handshake failed, figure out what went wrong
        if (handshakeError instanceof SSLHandshakeException
                && handshakeError.getCause() instanceof CertificateException) {
            // Path validation failed, or hostname validation failed on API level 16
            System.out.println("Path validation failed for " + serverHostname);
            shouldSendReport = true;
            certificateValidationResult = PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED;
            // We could NOT build a verified chain so we will send the chain sent by the server
            serverChainToSend = trustManager.getReceivedServerChain();
        }

        else if (handshakeError instanceof SSLPeerUnverifiedException) {
            // Hostname validation failed on API level 24
            // TODO(ad): Find and document at which API level this behavior changed
            System.out.println("Hostname validation failed for " + serverHostname);
            shouldSendReport = true;
            certificateValidationResult = PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED;
            serverChainToSend = trustManager.getVerifiedServerChain();
        }

        else if (handshakeError == null) {
            // No validation errors - perform pinning validation
            try {
                performPinningValidation(trustManager.getVerifiedServerChain(),
                        Arrays.asList(serverConfig.getPublicKeyHashes()));
            } catch (SSLPeerUnverifiedException e) {
                // Pinning validation failed
                System.out.println("Pinning validation failed for " + serverHostname);
                shouldSendReport = true;
                certificateValidationResult = PinValidationResult.FAILED;
                serverChainToSend = trustManager.getVerifiedServerChain();

                if (serverConfig.isEnforcePinning()) {
                    // If pinning is enforced, throw an exception to cancel the connection
                    handshakeError = e;
                }
            }
        }

        if (shouldSendReport) {
            TrustKit.getInstance().getReporter().pinValidationFailed(serverHostname, serverPort,
                    serverChainToSend, notedHostname, serverConfig, certificateValidationResult);
        }

        if (handshakeError != null) {
            // Forward any exception so we properly cancel the SSL handshake
            throw handshakeError;
        }
    }

    private static void performPinningValidation(List<Certificate> verifiedChain,
                                                 List<String> configuredSpkiPins)
            throws SSLPeerUnverifiedException {
        System.out.println("Performing pinning validation");
        boolean wasPinFound = false;
        for (Certificate certificate : verifiedChain) {
            String certificatePin = generatePublicKeyHash((X509Certificate) certificate);
            System.out.println("Testing " + certificatePin);
            if (configuredSpkiPins.contains(certificatePin)) {
                // Pinning validation succeeded
                System.out.println("Pin found!");
                wasPinFound = true;
                break;
            }
        }

        if (!wasPinFound) {
            StringBuilder errorBuilder = new StringBuilder()
                    .append("Pinning validation failed")
                    .append("\n  Configured pins: ");
            for (String pin : configuredSpkiPins) {
                errorBuilder.append(pin);
                errorBuilder.append(" ");
            }
            errorBuilder.append("\n  Peer certificate chain: ");
            for (Certificate certificate : verifiedChain) {
                errorBuilder.append("\n    ")
                        .append(generatePublicKeyHash((X509Certificate) certificate))
                        .append(" - ")
                        .append(((X509Certificate) certificate).getIssuerDN());
            }
            throw new SSLPeerUnverifiedException(errorBuilder.toString());
        }
        System.out.println("Pinning validation completed successfully");
    }

    private static String generatePublicKeyHash(X509Certificate certificate) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Should never happen");
        }
        digest.reset();

        byte[] spki = certificate.getPublicKey().getEncoded();
        byte[] spkiHash = digest.digest(spki);
        return Base64.encodeToString(spkiHash, Base64.DEFAULT).trim();
    }
}
