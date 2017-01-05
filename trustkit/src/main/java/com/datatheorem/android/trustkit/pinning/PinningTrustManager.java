package com.datatheorem.android.trustkit.pinning;

import android.net.http.X509TrustManagerExtensions;
import android.os.Build;
import android.support.annotation.NonNull;

import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.config.PublicKeyPin;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.net.ssl.X509TrustManager;



class PinningTrustManager implements X509TrustManager {


    // The trust manager we use to do the default SSL validation
    private final X509TrustManagerExtensions baselineTrustManager;

    private final String serverHostname;
    private final DomainPinningPolicy serverConfig;


    /**
     * A trust manager which implements path, hostname and pinning validation for a given hostname
     * and sends pinning failure reports if validation failed.
     *
     * Before Android N, the PinningTrustManager implements pinning validation itself. On Android
     * N and later the OS' implementation is used instead for pinning validation.
     *
     * @param serverHostname: The hostname of the server whose identity is being validated. It will
     *                      be validated against the name(s) the leaf certificate was issued for
     *                      when performing hostname validation.
     * @param serverConfig: The pinning policy to be enforced when doing pinning validation.
     * @param baselineTrustManager: The trust manager to use for path validation.
     */
    public PinningTrustManager(@NonNull String serverHostname,
                               @NonNull DomainPinningPolicy serverConfig,
                               @NonNull X509TrustManager baselineTrustManager) {
        // Store server's information
        this.serverHostname = serverHostname;
        this.serverConfig = serverConfig;

        // We use the default trust manager so we can perform regular SSL validation and we wrap it
        // in the Android-specific X509TrustManagerExtensions, which provides an API to compute the
        // cleaned/verified server certificate chain that we eventually need for pinning validation.
        // Also the X509TrustManagerExtensions provides a checkServerTrusted() where the hostname
        // can be supplied, allowing it to call the (system) RootTrustManager on Android N
        this.baselineTrustManager = new X509TrustManagerExtensions(baselineTrustManager);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
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

            validatedServerChain = baselineTrustManager.checkServerTrusted(chain, authType,
                    serverHostname);

        } catch (CertificateException e) {
            if ((Build.VERSION.SDK_INT >= 24)
                    && (e.getMessage().startsWith("Pin verification failed"))) {
                // A pinning failure triggered by the Android N netsec policy
                // This can only happen after path validation was successful
                didPinningValidationFail = true;
            } else {
                // Path or hostname validation failed
                didChainValidationFail = true;
            }
        }

        // Before Android N, manually perform pinning validation on the verified chain if path
        // validation succeeded. On Android N this was already taken care of by the netsec policy
        if ((Build.VERSION.SDK_INT < 24) && (!didChainValidationFail)) {

            boolean hasPinningPolicyExpired = (serverConfig.getExpirationDate() != null)
                    && (serverConfig.getExpirationDate().compareTo(new Date()) < 0);

            // Only do pinning validation if the policy has not expired
            if (!hasPinningPolicyExpired) {
                didPinningValidationFail = !isPinInChain(validatedServerChain,
                        serverConfig.getPublicKeyPins());
            }
        }

        // Send a pinning failure report if needed
        if (didChainValidationFail || didPinningValidationFail) {
            PinningValidationResult validationResult = PinningValidationResult.FAILED;
            if (didChainValidationFail) {
                // Hostname or path validation failed - not a pinning error
                validationResult = PinningValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED;
            }
            TrustManagerBuilder.getReporter().pinValidationFailed(serverHostname, 0,
                    servedServerChain, validatedServerChain, serverConfig, validationResult);
        }

        // Throw an exception if needed
        if (didChainValidationFail) {
            throw new CertificateException("Certificate validation failed for " + serverHostname);
        } else if ((didPinningValidationFail) && (serverConfig.shouldEnforcePinning())) {
            // Pinning failed and is enforced - throw an exception to cancel the handshake
            StringBuilder errorBuilder = new StringBuilder()
                    .append("Pin verification failed")
                    .append("\n  Configured pins: ");
            for (PublicKeyPin pin : serverConfig.getPublicKeyPins()) {
                errorBuilder.append(pin);
                errorBuilder.append(" ");
            }
            errorBuilder.append("\n  Peer certificate chain: ");
            for (Certificate certificate : validatedServerChain) {
                errorBuilder.append("\n    ")
                        .append(new PublicKeyPin(certificate))
                        .append(" - ")
                        .append(((X509Certificate) certificate).getIssuerDN());
            }
            throw new CertificateException(errorBuilder.toString());
        }
    }

    private static boolean isPinInChain(List<X509Certificate> verifiedServerChain,
                                        Set<PublicKeyPin> configuredPins) {
        boolean wasPinFound = false;
        for (Certificate certificate : verifiedServerChain) {
            PublicKeyPin certificatePin = new PublicKeyPin(certificate);
            if (configuredPins.contains(certificatePin)) {
                // Pinning validation succeeded
                wasPinFound = true;
                break;
            }
        }
        return wasPinFound;
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
        return new X509Certificate[0];
    }
}
