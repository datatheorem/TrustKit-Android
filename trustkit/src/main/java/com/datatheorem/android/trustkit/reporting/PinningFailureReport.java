package com.datatheorem.android.trustkit.reporting;

import android.support.annotation.NonNull;
import android.text.format.DateFormat;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.pinning.PinningValidationResult;
import com.datatheorem.android.trustkit.pinning.PublicKeyPin;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * A pinning validation failure report.
 */
class PinningFailureReport implements Serializable {
    // Fields specific to TrustKit reports
    private static final String APP_PLATFORM = "ANDROID";
    private static final String trustKitVersion = BuildConfig.VERSION_NAME;
    @NonNull private final String appBundleId;
    @NonNull private final String appVersion;
    @NonNull private final String appVendorId;
    @NonNull private final PinningValidationResult validationResult;

    // Fields from the HPKP spec
    @NonNull private final String serverHostname;
    private final int serverPort; // Not properly returned right now and will always be 0
    @NonNull private final String notedHostname;
    private final boolean includeSubdomains;
    private final boolean enforcePinning;
    @NonNull private final List<String> servedCertificateChainAsPem;
    @NonNull private final List<String> validatedCertificateChainAsPem;
    @NonNull private final Date dateTime;
    @NonNull private final Set<PublicKeyPin> knownPins;


    PinningFailureReport(@NonNull String appBundleId, @NonNull String appVersion,
                         @NonNull String appVendorId, @NonNull String hostname, int port,
                         @NonNull String notedHostname, boolean includeSubdomains,
                         boolean enforcePinning, @NonNull List<String> servedCertificateChain,
                         @NonNull List<String> validatedCertificateChain, @NonNull Date dateTime,
                         @NonNull Set<PublicKeyPin> knownPins,
                         @NonNull PinningValidationResult validationResult) {
        this.appBundleId = appBundleId;
        this.appVersion = appVersion;
        this.appVendorId = appVendorId;
        this.serverHostname = hostname;
        this.serverPort = port;
        this.notedHostname = notedHostname;
        this.includeSubdomains = includeSubdomains;
        this.enforcePinning = enforcePinning;
        this.servedCertificateChainAsPem = servedCertificateChain;
        this.validatedCertificateChainAsPem = validatedCertificateChain;
        this.dateTime = dateTime;
        this.knownPins = knownPins;
        this.validationResult = validationResult;
    }

    JSONObject toJson() {
        JSONObject jsonReport = new JSONObject();
        try {
            jsonReport.put("app-bundle-id", appBundleId);
            jsonReport.put("app-version", String.valueOf(appVersion));
            jsonReport.put("app-vendor-id", appVendorId);
            jsonReport.put("app-platform", APP_PLATFORM);
            jsonReport.put("trustkit-version", trustKitVersion);
            jsonReport.put("hostname", serverHostname);
            jsonReport.put("port", serverPort);
            jsonReport.put("noted-hostname", notedHostname);
            jsonReport.put("include-subdomains", includeSubdomains);
            jsonReport.put("enforce-pinning", enforcePinning);
            jsonReport.put("validation-result", validationResult.ordinal());
            jsonReport.put("date-time", DateFormat.format("yyyy-MM-dd'T'HH:mm:ssZ", dateTime));

            JSONArray ValidatedCertificateChainAsJson = new JSONArray();
            for (String validatedCertificate : validatedCertificateChainAsPem) {
                ValidatedCertificateChainAsJson.put(validatedCertificate);
            }
            jsonReport.put("validated-certificate-chain", ValidatedCertificateChainAsJson);

            JSONArray ServedCertificateChainAsJson = new JSONArray();
            for (String validatedCertificate : servedCertificateChainAsPem) {
                ServedCertificateChainAsJson.put(validatedCertificate);
            }
            jsonReport.put("served-certificate-chain", ServedCertificateChainAsJson);

            JSONArray jsonArrayKnownPins = new JSONArray();
            for (PublicKeyPin knownPin : knownPins) {
                jsonArrayKnownPins.put("pin-sha256=\"" + knownPin.toString() + "\"");
            }
            jsonReport.put("known-pins", jsonArrayKnownPins);

        } catch (JSONException ex) {
            // Should never happen
            throw new IllegalStateException("JSON error for report: " + this.toString());
        }
        return jsonReport;
    }

    @Override
    public String toString() {
        try {
            return toJson().toString(2);
        } catch (JSONException e) {
            return toJson().toString();
        }
    }

    @NonNull
    String getNotedHostname() {
        return notedHostname;
    }

    @NonNull
    String getServerHostname() {
        return serverHostname;
    }

    @NonNull
    List<String> getValidatedCertificateChainAsPem() {
        return validatedCertificateChainAsPem;
    }

    @NonNull
    PinningValidationResult getValidationResult() {
        return validationResult;
    }

    int getServerPort() {
        return serverPort;
    }
}
