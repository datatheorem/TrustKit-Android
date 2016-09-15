package com.datatheorem.android.trustkit.pinning;

import android.net.http.X509TrustManagerExtensions;
import android.os.Build;
import android.support.annotation.NonNull;
import android.util.Base64;

import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.config.TrustKitConfiguration;

import java.lang.reflect.Array;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


class PinningTrustManager implements X509TrustManager {

    private static final X509TrustManagerExtensions systemTrustManager;
    static {
        // Retrieve the default trust manager so we can perform regular SSL validation and wrap it
        // in the Android-specific X509TrustManagerExtensions, which provides an API to compute the
        // cleaned/verified server certificate chain that we eventually need for pinning validation
        systemTrustManager = new X509TrustManagerExtensions(getSystemTrustManager());
    }

    private final String serverHostname;
    private final PinnedDomainConfiguration serverConfig;


    public PinningTrustManager(String serverHostname) {
        this.serverHostname = serverHostname;
        TrustKitConfiguration config = TrustKit.getInstance().getConfiguration();
        this.serverConfig = config.get(serverHostname);
    }

    // Retrieve the platform's default trust manager. Depending on the device's API level, the trust
    // manager will consecutively do path validation (all API levels), hostname validation
    // (API level 16 to ???), and pinning validation if a network policy was configured (API level
    // 24+)
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
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {

        // If the domain is not pinned, do not do interfere and do the default validation
        if (serverConfig == null) {
            systemTrustManager.checkServerTrusted(chain, authType, serverHostname);
            return;
        }

        // If the domain is pinned, let's do our validation
        boolean didChainValidationFail = false; // Includes path and hostname validation
        boolean didPinningValidationFail = false;

        // Store the received chain so we can send it later in a report if path validation fails
        List<X509Certificate> servedServerChain = Arrays.asList((X509Certificate [])chain);
        List<X509Certificate> validatedServerChain = servedServerChain;

        // Then do hostname validation first
        // During the normal flow, this is done at very different times during the SSL handshake,
        // depending on the device's API level; we just do it here to ensure it is always done
        // consistently
        if (!OkHostnameVerifier.INSTANCE.verify(serverHostname, chain[0])) {
            didChainValidationFail = true;
        }

        // Then do the system's SSL validation and try to compute the verified chain, which includes
        // the root certificate from the Android trust store and removes unrelated
        // extra certificates an attacker might add: https://koz.io/pinning-cve-2016-2402/
        try {
            validatedServerChain = systemTrustManager.checkServerTrusted(chain, authType,
                    serverHostname);

        } catch (CertificateException e) {
            if ((Build.VERSION.SDK_INT >= 24)
                    && (e.getMessage().startsWith("Pin verification failed"))) {
                // A pinning failure triggered by the Android N netsec policy
                // TODO(ad): Check if it does path validation first so that we're not silencing
                // that error when enforcePinning is false
                didPinningValidationFail = true;
            } else {
                // Path or hostname validation failed
                didChainValidationFail = true;
            }
        }

        // Before Android N, manually perform pinning validation on the verified chain if path
        // validation succeeded. On Android N this was already taken care of by the netsec policy
        if ((Build.VERSION.SDK_INT < 24) && (!didChainValidationFail)) {
            didPinningValidationFail = !isPinInChain(validatedServerChain,
                    new HashSet<>(Arrays.asList(serverConfig.getPublicKeyHashes())));
        }


        // Send a pinning failure report if needed
        if (didChainValidationFail || didPinningValidationFail) {
            PinValidationResult validationResult = PinValidationResult.FAILED;
            if (didChainValidationFail) {
                validationResult = PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED;
            }
            TrustKit.getInstance().getReporter().pinValidationFailed(serverHostname, 0,
                    servedServerChain, validatedServerChain,
                    serverHostname, serverConfig, validationResult);
        }

        // Throw an exception if needed
        if (didChainValidationFail) {
            throw new CertificateException("Certificate validation failed for " + serverHostname);
        }
        else if ((didPinningValidationFail) && (serverConfig.isEnforcePinning())) {
            // Pinning failed and is enforced - throw an exception to cancel the handshake
            StringBuilder errorBuilder = new StringBuilder()
                    .append("Pin verification failed")
                    .append("\n  Configured pins: ");
            for (String pin : serverConfig.getPublicKeyHashes()) {
                errorBuilder.append(pin);
                errorBuilder.append(" ");
            }
            errorBuilder.append("\n  Peer certificate chain: ");
            for (Certificate certificate : validatedServerChain) {
                errorBuilder.append("\n    ")
                        .append(generatePublicKeyHash(certificate))
                        .append(" - ")
                        .append(((X509Certificate) certificate).getIssuerDN());
            }
            throw new CertificateException(errorBuilder.toString());
        }
    }

    private static boolean isPinInChain(List<X509Certificate> verifiedServerChain,
                                        Set<String> configuredPins) {
        boolean wasPinFound = false;
        for (Certificate certificate : verifiedServerChain) {
            String certificatePin = generatePublicKeyHash(certificate);
            if (configuredPins.contains(certificatePin)) {
                // Pinning validation succeeded
                wasPinFound = true;
                break;
            }
        }
        return wasPinFound;
    }

    private static String generatePublicKeyHash(Certificate certificate) {
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
        // getAcceptedIssuers is meant to be used to determine which trust anchors the server will
        // accept when verifying clients.
        return null;
    }
}