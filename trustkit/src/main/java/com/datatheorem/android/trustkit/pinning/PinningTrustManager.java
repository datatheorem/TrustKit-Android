package com.datatheorem.android.trustkit.pinning;

import android.net.http.X509TrustManagerExtensions;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;

import com.datatheorem.android.trustkit.TrustKit;
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



@RequiresApi(api = 17)
class PinningTrustManager implements X509TrustManager {

    // The trust manager we use to do the default SSL validation
    private final X509TrustManagerExtensions baselineTrustManager;

    private final String serverHostname;


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
     * @param baselineTrustManager: The trust manager to use for path validation.
     */
    public PinningTrustManager(@NonNull String serverHostname,
                               @NonNull X509TrustManager baselineTrustManager) {
        // Store server's information
        this.serverHostname = null;

        if (Build.VERSION.SDK_INT < 17) {
            // No pinning validation at all for API level < 17
            // Because X509TrustManagerExtensions is not available
            this.baselineTrustManager = null;
        } else {
            // We use the default trust manager so we can perform regular SSL validation and we wrap
            // it in the Android-specific X509TrustManagerExtensions, which provides an API to
            // compute the cleaned/verified server certificate chain that we eventually need for
            // pinning validation. Also the X509TrustManagerExtensions provides a
            // checkServerTrusted() where the hostname can be supplied, allowing it to call the
            // (system) RootTrustManager on Android N
            this.baselineTrustManager = new X509TrustManagerExtensions(baselineTrustManager);
        }
    }

    /**
     * A trust manager which implements path, hostname and pinning validation for a given hostname
     * and sends pinning failure reports if validation failed.
     *
     * Build version Android N and above pass the host name to the trust manager, so no need to pass it
     * here in the constructor.
     * Before Android N, the PinningTrustManager implements pinning validation itself. On Android
     * N and later the OS' implementation is used instead for pinning validation.
     *
     * @param baselineTrustManager: The trust manager to use for path validation.
     */
    @RequiresApi(api = Build.VERSION_CODES.N)
    public PinningTrustManager(@NonNull X509TrustManager baselineTrustManager) {
        serverHostname = "";
        this.baselineTrustManager = new X509TrustManagerExtensions(baselineTrustManager);
    }

    /**
     * This methods gets called on Android N instead of the 2-parameter checkServerTrusted().
     *
     * If we ever drop support for versions before Android N (unlikely), we can use this method
     * to automatically get the hostname when the certificate chain needs to be validated, instead
     * of having to ask for the hostname a lot earlier when the trust manager (or socket factory)
     * gets created, making the API a lot nicer.
     *
     * For now this is here only for documentation.
     * See also: https://developer.android.com/reference/javax/net/ssl/X509ExtendedTrustManager.html
     * not to be confused with X509TrustManagerExtensions!
     *
     */

    public List<X509Certificate> checkServerTrusted(X509Certificate[] chain, String authType,
                                                    String host) throws CertificateException {
        if (host == null || host.trim().length() == 0){
            throw new CertificateException("host name is null or empty");
        }

        boolean didChainValidationFail = false; // Includes path and hostname validation
        boolean didPinningValidationFail = false;
        DomainPinningPolicy serverConfig =
                TrustKit.getInstance().getConfiguration().getPolicyForHostname(host);

        // Store the received chain so we can send it later in a report if path validation fails
        List<X509Certificate> servedServerChain = Arrays.asList((X509Certificate [])chain);
        List<X509Certificate> validatedServerChain = servedServerChain;

        // Then do hostname validation first
        // During the normal flow, this is done at very different times during the SSL handshake,
        // depending on the device's API level; we just do it here to ensure it is always done
        // consistently
        if (!OkHostnameVerifier.INSTANCE.verify(host, chain[0])) {
            didChainValidationFail = true;
        }

        // Then do the system's SSL validation and try to compute the verified chain, which includes
        // the root certificate from the Android trust store and removes unrelated
        // extra certificates an attacker might add: https://koz.io/pinning-cve-2016-2402/
        try {

            validatedServerChain = baselineTrustManager.checkServerTrusted(chain, authType,
                    host);

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

            PinningValidationResult pinningValidationResult = PinningValidator.evaluateTrust(validatedServerChain.toArray(new X509Certificate[validatedServerChain.size()]), serverHostname);
            didChainValidationFail = pinningValidationResult == PinningValidationResult.FAILED;
        }

        // Send a pinning failure report if needed
        if (didChainValidationFail || didPinningValidationFail && (Build.VERSION.SDK_INT >= 24)) {
            PinningValidationResult validationResult = PinningValidationResult.FAILED;
            if (didChainValidationFail) {
                // Hostname or path validation failed - not a pinning error
                validationResult = PinningValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED;
            }
            TrustManagerBuilder.getReporter().pinValidationFailed(host, 0,
                    servedServerChain, validatedServerChain, serverConfig, validationResult);
        }

        // Throw an exception if needed
        if (didChainValidationFail) {
            throw new CertificateException("Certificate validation failed for " + host);
        } else if ((didPinningValidationFail) && (serverConfig != null) && (serverConfig.shouldEnforcePinning())) {
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
                        .append(((X509Certificate) certificate).getSubjectDN());
            }
            throw new CertificateException(errorBuilder.toString());
        }

        return validatedServerChain;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        checkServerTrusted(chain, authType, serverHostname);
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
