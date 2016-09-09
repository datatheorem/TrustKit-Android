package com.datatheorem.android.trustkit.pinning;

import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


public class PinningTrustManager implements X509TrustManager {

    private X509TrustManager systemTrustManager;

    public PinningTrustManager(String hostname, Integer serverPort, String notedHostname, PinnedDomainConfiguration configuration) {
        // Retrieve the default trust manager so we can perform regular SSL validation
        systemTrustManager = getSystemTrustManager();
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
            System.out.println(trustManager);

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
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException
    {
        // Perform default certificate validation
        systemTrustManager.checkServerTrusted(chain, authType);
        System.out.println("LOLOLOL " + authType);

        // TODO(ad): Add pinning validation
        // TODO(ad): Generate report
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }
}