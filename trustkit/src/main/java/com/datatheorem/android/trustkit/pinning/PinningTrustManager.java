package com.datatheorem.android.trustkit.pinning;

import java.security.KeyStore;
import java.security.KeyStoreException;
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

// Needed so we can do pinning validation after hostname validation (to avoid wrong pinning errors and reports)
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

    // The list of certificates sent by the server
    private List<Certificate> receivedServerChain = null;

    // The server's verified certificate chain, only available if path validation succeeded
    private List<Certificate> verifiedServerChain = null;

    // TODO(ad): Rename this class
    public PinningTrustManager() {
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
        // Store the received chain so we can send it in a report if path validation fails
        receivedServerChain = Arrays.asList((Certificate [])chain);

        // Perform default path validation - will throw an exception if it failed
        // This also does hostname validation on API level 16
        // TODO(ad): Find why API level where this behavior changed
        System.out.println("Performing system path validation");
        systemTrustManager.checkServerTrusted(chain, authType);

        // Build the verified certificate chain, which includes the root certificate from the
        // Android trust store and removes unrelated extra certificates an attacker might add
        // https://koz.io/pinning-cve-2016-2402/
        try {
            // Keep the verified chain around so we can later use it for pinning validation
            verifiedServerChain = chainCleaner.clean(Arrays.asList((Certificate[]) chain));
        } catch (SSLPeerUnverifiedException e) {
            // Should never happen since the system validation already succeeded
            // Throw the exception to close the SSL connection anyway
            throw new CertificateException("Received SSLPeerUnverifiedException from " +
                    "CertificateChainCleaner; received certificate chain is unclean.");
        }
        System.out.println("System path validation completed successfully");
    }

    public List<Certificate> getVerifiedServerChain() { return verifiedServerChain; }

    public List<Certificate> getReceivedServerChain() { return receivedServerChain; }


    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}