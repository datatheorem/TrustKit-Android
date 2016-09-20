package com.datatheorem.android.trustkit.pinning;

import android.support.annotation.NonNull;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


/**
 * Used when <debug-overrides> is enabled in the network security policy and we are on a pre-N
 * Android device (as Android N automatically takes care of this). It first tries to validate
 * the server's certificate chain using the system's default trust manager, and then using a trust
 * manager configured with custom CAs (the ones defined in <debug-overrides>).
 */
class DebugOverridesTrustManager implements X509TrustManager {

    // The trust manager we use to do the default SSL validation
    private final X509TrustManager systemTrustManager;

    // A trust manager configured with custom/debug CA certificates
    private final X509TrustManager customCaTrustManager;

    public DebugOverridesTrustManager(@NonNull String debugCaFilePath)
            throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException,
            KeyManagementException {
        customCaTrustManager = getCustomCaTrustManager(debugCaFilePath);
        systemTrustManager = SystemTrustManager.getDefault();
    }

    private static X509TrustManager getCustomCaTrustManager(String debugCaFilePath) throws
            CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        X509TrustManager debugTrustManager = null;

        // Copied & pasted from https://developer.android.com/training/articles/security-ssl.html
        // Load CAs from an InputStream
        CertificateFactory cf;
        cf = CertificateFactory.getInstance("X.509");

        InputStream caInput = new BufferedInputStream(new FileInputStream(debugCaFilePath));
        Certificate ca;
        try {
            ca = cf.generateCertificate(caInput);
            System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN());
        } finally {
            caInput.close();
        }

        // Create a KeyStore containing our trusted CAs
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);

        // Create a TrustManager that trusts the CAs in our KeyStore
        String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(tmfAlgorithm);
        trustManagerFactory.init(keyStore);
        trustManagerFactory.getTrustManagers();

        for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager) {
                debugTrustManager = (X509TrustManager) trustManager;
            }
        }

        if (debugTrustManager == null) {
            throw new IllegalStateException("Should never happen");
        }
        return debugTrustManager;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        try {
            systemTrustManager.checkServerTrusted(chain, authType);
        } catch (CertificateException e) {
            // Try validating with the custom CAs
            customCaTrustManager.checkServerTrusted(chain, authType);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        throw new CertificateException("Client certificates not supported!");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        // getAcceptedIssuers is meant to be used to determine which trust anchors the server will
        // accept when verifying clients.
        return null;
    }
}
