package com.datatheorem.android.trustkit.pinning;

import android.support.annotation.NonNull;
import android.util.Base64;

import com.datatheorem.android.trustkit.PinValidationResult;

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

    // The list pins (Base64-encoded SHA256 of the subject public key info) for this server
    // TODO(ad): Use a special type for the pins?
    private final List<String> spkiPins;

    // The list of certificates sent by the server
    private Certificate[] serverReceivedChain = null;

    // The server's verified certificate chain, only available if path validation succeeded
    private Certificate[] serverVerifiedChain = null;

    private PinValidationResult serverChainValidationResult;


    public PinningTrustManager(@NonNull String[] spkiPins) {
        this.spkiPins = Arrays.asList(spkiPins);
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
        serverReceivedChain = chain;

        // Perform default certificate validation
        System.out.println("Performing default system validation");
        try {
            systemTrustManager.checkServerTrusted(chain, authType);
        } catch (CertificateException e) {
            // Store the result and re-throw the exception to close the SSL connection
            serverChainValidationResult = PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED;
            throw e;
        }

        // Build the verified certificate chain, which includes the root certificate from the
        // Android trust store and removes unrelated extra certificates an attacker might add
        // https://koz.io/pinning-cve-2016-2402/
        List<Certificate> verifiedChain;
        try {
            verifiedChain = chainCleaner.clean(Arrays.asList((Certificate[]) chain));
        } catch (SSLPeerUnverifiedException e) {
            // Should never happen since the system validation already succeeded
            // Store the result and re-throw the exception to close the SSL connection
            serverChainValidationResult = PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED;
            throw new CertificateException("Received SSLPeerUnverifiedException from " +
                    "CertificateChainCleaner; received certificate chain is unclean.");
        }

        // Keep the verified chain around so we can retrieve it when sending reports
        serverVerifiedChain = verifiedChain.toArray(new Certificate[verifiedChain.size()]);

        // Perform pinning validation
        System.out.println("Performing pinning validation");
        boolean wasPinFound = false;
        for (Certificate certificate : verifiedChain) {
            String certificatePin = generatePublicKeyHash((X509Certificate) certificate);
            System.out.println("Testing " + certificatePin);
            if (spkiPins.contains(certificatePin)) {
                // Pinning validation succeeded
                System.out.println("Pin found!");
                wasPinFound = true;
                break;
            }
        }

        if (!wasPinFound) {
            // Store the result
            serverChainValidationResult = PinValidationResult.FAILED;

            // Then throw an exception to close the SSL connection
            StringBuilder errorBuilder = new StringBuilder()
                    .append("Pinning validation failed")
                    .append("\n  Configured pins: ")
                    .append("\n  Peer certificate chain: ");
            for (Certificate certificate : serverVerifiedChain) {
                errorBuilder.append("\n    ")
                        .append(generatePublicKeyHash((X509Certificate) certificate))
                        .append(" - ")
                        .append(((X509Certificate) certificate).getIssuerDN());
            }
            throw new CertificateException(errorBuilder.toString());
        }
        System.out.println("Path and pinning validation completed successfully");
    }

    public Certificate[] getServerVerifiedChain() { return serverVerifiedChain; }

    public Certificate[] getServerReceivedChain() { return serverReceivedChain; }

    public PinValidationResult getServerChainValidationResult() {
        return serverChainValidationResult;
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