package com.datatheorem.android.trustkit.pinning;


import android.support.annotation.NonNull;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


class SystemTrustManager {

    /**
     * Retrieve the platform's default trust manager.
     * Depending on the device's API level, the trust manager will consecutively do path validation
     * (all API levels), hostname validation (API level 16 to ???), and pinning validation if a
     * network policy was configured (API level 24+).
     *
     * @return the platform's default trust manager.
     */
    @NonNull
    public static X509TrustManager getDefault() {
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

        if (systemTrustManager == null) {
            throw new IllegalStateException("Should never happen");
        }
        return systemTrustManager;
    }
}
