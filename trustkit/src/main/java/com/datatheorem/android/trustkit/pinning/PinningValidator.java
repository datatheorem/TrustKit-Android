package com.datatheorem.android.trustkit.pinning;

import android.os.Build;
import android.support.annotation.RequiresApi;
import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.config.PublicKeyPin;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;

@RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
public class PinningValidator {

    public static PinningValidationResult evaluateTrust(X509Certificate[] serverChain, String serverHostname){
        DomainPinningPolicy serverConfig =
                TrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname);
        List<X509Certificate> serverChainAsList = Arrays.asList(serverChain);

        if (serverConfig == null) {
            // Domain is NOT pinned or there is a debug override - only do baseline validation
            return PinningValidationResult.SUCCESS;
        }

        boolean hasPinningPolicyExpired = (serverConfig.getExpirationDate() != null)
                && (serverConfig.getExpirationDate().compareTo(new Date()) < 0);

        boolean didPinningValidationFail = false;

        // Only do pinning validation if the policy has not expired
        if (!hasPinningPolicyExpired) {
            didPinningValidationFail = !isPinInChain(serverChainAsList,
                    serverConfig.getPublicKeyPins());
        }

        PinningValidationResult validationResult = PinningValidationResult.FAILED;

        if (didPinningValidationFail) {
            validationResult = PinningValidationResult.FAILED;
            TrustManagerBuilder.getReporter().pinValidationFailed(serverHostname, 0,
                    serverChainAsList, serverChainAsList, serverConfig, validationResult);
        }

        if (!didPinningValidationFail || !serverConfig.shouldEnforcePinning()){
            validationResult = PinningValidationResult.SUCCESS;
        }

        return validationResult;
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
}
