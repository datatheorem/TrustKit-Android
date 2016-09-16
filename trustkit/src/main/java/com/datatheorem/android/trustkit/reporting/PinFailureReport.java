package com.datatheorem.android.trustkit.reporting;

import android.text.format.DateFormat;

import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.pinning.SubjectPublicKeyInfoPin;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.Serializable;
import java.sql.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * A pinning validation failure report.
 */
// TODO(ad): Remove public
public class PinFailureReport implements Serializable {
    // Fields specific to TrustKit reports
    private static final String APP_PLATFORM = "ANDROID";
    private String appBundleId;
    private String appVersion;
    private String appVendorId;
    private String trustKitVersion;
    private PinValidationResult validationResult;

    // Fields from the HPKP spec
    private String serverHostname;
    private int serverPort; // Not properly returned right now and will always be 0
    private String notedHostname;
    private boolean includeSubdomains;
    private boolean enforcePinning;
    private List<String> servedCertificateChainAsPem;
    private List<String> validatedCertificateChainAsPem;
    private Date dateTime;
    private Set<SubjectPublicKeyInfoPin> knownPins;

    // TODO(ad): Remove public
    public PinFailureReport(String appBundleId, String appVersion, String appVendorId,
                            String trustKitVersion, String hostname, int port,
                            String notedHostname, boolean includeSubdomains,
                            boolean enforcePinning, List<String> servedCertificateChain,
                            List<String> validatedCertificateChain, Date dateTime,
                            Set<SubjectPublicKeyInfoPin> knownPins,
                            PinValidationResult validationResult) {
        this.appBundleId = appBundleId;
        this.appVersion = appVersion;
        this.appVendorId = appVendorId;
        this.trustKitVersion = trustKitVersion;
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

    public JSONObject toJson() {
        JSONObject jsonReport = new JSONObject();
        try {
            jsonReport.put("app-bundle-id", appBundleId);
            jsonReport.put("app-version", String.valueOf(appVersion));
            jsonReport.put("app-vendor-id", appVendorId);
            jsonReport.put("app-platform", APP_PLATFORM);
            jsonReport.put("trustkit-version", trustKitVersion);
            jsonReport.put("hostname", serverHostname);
            jsonReport.put("serverPort", serverPort);
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
            for (SubjectPublicKeyInfoPin knownPin : knownPins) {
                jsonArrayKnownPins.put(knownPin.toString());
            }
            jsonReport.put("known-pins", jsonArrayKnownPins);

        } catch (JSONException ex) {
            // Should never happen
            throw new IllegalStateException("JSON error for report:" + this.toString());
        }
        return jsonReport;
    }

    @Override
    public String toString() {
        return toJson().toString();
    }

    // TODO(ad): Remove this
    public String[] pinsToString(Set<SubjectPublicKeyInfoPin> pins) {
        ArrayList<String> pinsString = new ArrayList<>();
        for (SubjectPublicKeyInfoPin pin : pins) {
            pinsString.add(pin.toString());
        }

        return pinsString.toArray(new String[pinsString.size()]);
    }

    public String getNotedHostname() {
        return notedHostname;
    }

    public String getServerHostname() {
        return serverHostname;
    }

    public List<String> getValidatedCertificateChainAsPem() {
        return validatedCertificateChainAsPem;
    }

    public PinValidationResult getValidationResult() {
        return validationResult;
    }

    public int getServerPort() {
        return serverPort;
    }
}
