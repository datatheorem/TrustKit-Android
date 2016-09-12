package com.datatheorem.android.trustkit.pinning;

import android.util.Base64;

import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


class PinningTrustManager implements X509TrustManager {

    private static final X509TrustManager systemTrustManager;
    static {
        // Retrieve the default trust manager so we can perform regular SSL validation
        systemTrustManager = getSystemTrustManager();
    }

    private static final CertificateChainCleaner chainCleaner;
    static {
        // TODO(ad): Does the TrustRootIndex work on all Android versions we support?
        // Documentation says it shouldn't be used in Android API 17 or better
        chainCleaner = new CertificateChainCleaner(TrustRootIndex.get(systemTrustManager));
    }

    private final String serverHostname;
    private final int serverPort;
    private final String notedHostname; // TODO(ad): Put this in the serverConfig
    private final PinnedDomainConfiguration serverConfig; // null if the domain is not pinned

    public PinningTrustManager(String serverHostname, int serverPort, String notedHostname,
                               PinnedDomainConfiguration serverConfig) {

        System.out.println("Initialized trust manager with" + serverHostname + ":" + serverPort
                + " " + notedHostname + " " + serverConfig);

        this.serverHostname = serverHostname;
        this.serverPort = serverPort;
        this.notedHostname = notedHostname;
        this.serverConfig = serverConfig;
    }

    private static X509TrustManager getSystemTrustManager() {
        X509TrustManager systemTrustManager = null;
        TrustManagerFactory trustManagerFactory;
        try {
            trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm()
            );
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Should never happen");
        }

        try {
            trustManagerFactory.init((KeyStore)null);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Should never happen");
        }

        for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager) {
                systemTrustManager = (X509TrustManager)trustManager;
            }
        }
        return systemTrustManager;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        throw new CertificateException("Client certificates not supported!");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws
            CertificateException {
        // Perform default certificate validation
        System.out.println("Performing default system validation");
        try {
            systemTrustManager.checkServerTrusted(chain, authType);
        } catch (CertificateException e) {
            // Send a pin failure report
            if (serverConfig != null) {
                TrustKit.getInstance().getReporter().pinValidationFailed(serverHostname, serverPort,
                        chain, notedHostname, serverConfig,
                        PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED);
            }

            // Then re-throw the exception to close the SSL connection
            throw e;
        }

        // Perform pinning validation if the domain is pinned
        if (serverConfig != null) {
            System.out.println("Performing pinning validation");

            // Build the verified certificate chain, which includes the root certificate from the
            // Android trust store and removes unrelated extra certificates an attacker might add
            // https://koz.io/pinning-cve-2016-2402/
            List<Certificate> verifiedChain;
            try {
                verifiedChain = chainCleaner.clean(Arrays.asList((Certificate[]) chain));
            } catch (SSLPeerUnverifiedException e) {
                // Send a pin failure report
                TrustKit.getInstance().getReporter().pinValidationFailed(serverHostname, serverPort,
                        chain, notedHostname, serverConfig,
                        PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED);

                // Then re-throw the exception to close the SSL connection
                throw new CertificateException("Received SSLPeerUnverifiedException from " +
                        "CertificateChainCleaner; received certificate chain is unclean.");
            }

            // Perform pinning validation
            boolean wasPinFound = false;
            List<String> serverPins = Arrays.asList(serverConfig.getPublicKeyHashes());
            for (Certificate certificate : verifiedChain) {
                String certificatePin = generatePublicKeyHash((X509Certificate) certificate);

                System.out.println("Testing " + certificatePin);
                if (serverPins.contains(certificatePin)) {
                    // Pinning validation succeeded
                    System.out.println("Pin found!");
                    wasPinFound = true;
                    break;
                }
            }

            if (!wasPinFound) {
                // Send a pin failure report
                TrustKit.getInstance().getReporter().pinValidationFailed(serverHostname, serverPort,
                        chain, notedHostname, serverConfig, PinValidationResult.FAILED);

                // Then throw the exception to close the SSL connection
                StringBuilder errorBuilder = new StringBuilder()
                        .append("Pinning validation failed for ")
                        .append(serverHostname)
                        .append("\n  Configured pins: ")
                        .append(serverPins)
                        .append("\n  Peer certificate chain: ");
                for (Certificate certificate : chain) {
                    errorBuilder.append("\n    ")
                            .append(generatePublicKeyHash((X509Certificate) certificate))
                            .append(" - ")
                            .append(((X509Certificate) certificate).getIssuerDN());
                }
                throw new CertificateException(errorBuilder.toString());
            }

            // If we get here, validation succeeded
            // TOOD(ad): Send a broadcast notification
        }
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

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}