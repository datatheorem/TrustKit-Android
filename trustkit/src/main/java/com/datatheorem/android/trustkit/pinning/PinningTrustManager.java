package com.datatheorem.android.trustkit.pinning;

import android.util.Base64;

import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;

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

    private final CertificateChainCleaner chainCleaner;
    private final X509TrustManager systemTrustManager;
    private final String serverHostname;
    private final int serverPort;
    private final String notedHostname; // TODO(ad): Put this in the serverConfig
    private final PinnedDomainConfiguration serverConfig; // null if the domain is not pinned

    public PinningTrustManager(String serverHostname, int serverPort, String notedHostname,
                               PinnedDomainConfiguration serverConfig) {

        System.out.println("Initialized trust manager with" + serverHostname + ":" + serverPort
                + " " + notedHostname + " " + serverConfig);

        // Retrieve the default trust manager so we can perform regular SSL validation
        systemTrustManager = getSystemTrustManager();
        chainCleaner = new CertificateChainCleaner(TrustRootIndex.get(systemTrustManager));

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
            PinValidationResult result = PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED;
            TrustKit.getInstance().getReporter().pinValidationFailed(serverHostname, serverPort,
                    chain, notedHostname, serverConfig, result);

            // Then re-throw the exception to close the SSL connection
            throw e;
        }

        // Perform pinning validation if the domain is pinned
        if (serverConfig != null) {
            System.out.println("Performing pinning validation");

            // Clean the certificate chain to avoid SSL pinning bypass issues
            // https://koz.io/pinning-cve-2016-2402/
            List<Certificate> cleanedChainList;
            try {
                cleanedChainList = chainCleaner.clean(Arrays.asList((Certificate[]) chain));
            } catch (SSLPeerUnverifiedException e) {
                // Send a pin failure report
                PinValidationResult result =
                        PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED;
                TrustKit.getInstance().getReporter().pinValidationFailed(serverHostname, serverPort,
                        chain, notedHostname, serverConfig, result);

                // Then re-throw the exception to close the SSL connection
                throw new CertificateException("Received SSLPeerUnverifiedException from " +
                        "CertificateChainCleaner; received certificate chain is unclean.");
            }

            // Perform pinning validation
            boolean wasPinFound = false;
            List<String> serverPins = Arrays.asList(serverConfig.getPublicKeyHashes());
            for (Certificate certificate : cleanedChainList) {
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
                PinValidationResult result = PinValidationResult.FAILED;
                TrustKit.getInstance().getReporter().pinValidationFailed(serverHostname, serverPort,
                        chain, notedHostname, serverConfig, result);

                // TODO(ad): Add more details to this exception (configured pins, etc.)
                throw new CertificateException("Pinning validation failed");
            }
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