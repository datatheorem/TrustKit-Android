package com.datatheorem.android.trustkit.pinning;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Set;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


/**
 * Used when <debug-overrides> is enabled in the network security policy and we are on a pre-N
 * Android device (as Android N automatically takes care of this). It returns a trust manager that
 * trusts the supplied debug CA certificates, in addition to the Android system and user CA
 * certificates.
 */
class DebugOverridesTrustManager {

    public static X509TrustManager getInstance(Set<Certificate> debugCaCerts) throws
            CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        X509TrustManager debugTrustManager = null;

        // Create a KeyStore containing our trusted CAs and the Android user and system CAs
        KeyStore systemKeyStore = KeyStore.getInstance("AndroidCAStore");
        systemKeyStore.load(null, null);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        // Copy the user and system CAs from the Android store - is there a faster way to do this?
        Enumeration aliases = systemKeyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = (String) aliases.nextElement();
            X509Certificate cert = (X509Certificate) systemKeyStore.getCertificate(alias);
            keyStore.setCertificateEntry(alias , cert);
        }

        // Add the extra debug CAs to the store
        for (Certificate caCert : debugCaCerts) {
            String alias = "debug: " + ((X509Certificate) caCert).getSubjectDN().getName();
            keyStore.setCertificateEntry(alias , caCert);
        }

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
}