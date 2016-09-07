package com.datatheorem.android.trustkit.report;

import android.text.format.DateFormat;

import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.Serializable;
import java.sql.Date;
import java.util.Arrays;

/**
 * Data representation of a pinning validation failure
 */
class PinFailureReport implements Serializable {
    private String appBundleId;
    private String appVersion;
    private String appVendorId;
    private String appPlatform;
    private String trustKitVersion;
    //called serverHostname
    private String serverHostname;
    private int port;
    //pinned serverHostname checked
    private String notedHostname;
    private boolean includeSubdomains;
    private boolean enforcePinning;
    private String[] validatedCertificateChain;
    private Date dateTime;
    private String[] knownPins;
    private int validationResult;

    private PinFailureReport(Builder builder) {
        appBundleId = builder.appBundleId;
        appVersion = builder.appVersion;
        appVendorId = builder.appVendorId;
        appPlatform = builder.appPlatform;
        trustKitVersion = builder.trustKitVersion;
        serverHostname = builder.hostname;
        port = builder.port;
        notedHostname = builder.notedHostname;
        includeSubdomains = builder.includeSubdomains;
        enforcePinning = builder.enforcePinning;
        validatedCertificateChain = builder.validatedCertificateChain;
        dateTime = builder.dateTime;
        knownPins = builder.knownPins;
        validationResult = builder.validationResult.ordinal();
    }

    public String getNotedHostname() {
        return notedHostname;
    }

    public String getServerHostname() {
        return serverHostname;
    }

    public String[] getValidatedCertificateChain() {
        return validatedCertificateChain;
    }

    public int getValidationResult() {
        return validationResult;
    }

    public int getPort() {
        return port;
    }

    public String[] getKnownPins() {
        return knownPins;
    }

    public JSONObject toJson() {
        try {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("app-bundle-id", appBundleId);
            jsonObject.put("app-version", String.valueOf(appVersion));
            jsonObject.put("app-vendor-id", appVendorId);
            jsonObject.put("app-platform", appPlatform);
            jsonObject.put("trustkit-version", trustKitVersion);
            jsonObject.put("hostname", serverHostname);
            jsonObject.put("port", port);
            jsonObject.put("noted-hostname", notedHostname);
            jsonObject.put("include-subdomains", includeSubdomains);
            jsonObject.put("enforce-pinning", enforcePinning);

            JSONArray jsonArrayValidatedCertificateChain = new JSONArray();

            for (String validatedCertificate : validatedCertificateChain) {
                jsonArrayValidatedCertificateChain.put(validatedCertificate);
            }

            jsonObject.put("validated-certificate-chain", jsonArrayValidatedCertificateChain);

            jsonObject.put("date-time", DateFormat.format("yyyy-MM-dd'T'HH:mm:ssZ", dateTime));

            JSONArray jsonArrayKnownPins = new JSONArray();
            for (String knownPin : knownPins) {
                jsonArrayKnownPins.put(knownPin);
            }

            jsonObject.put("known-pins", jsonArrayKnownPins);
            jsonObject.put("validation-result", validationResult);

            return jsonObject;

        } catch (JSONException ex) {
            TrustKitLog.e(" JSON serialization error, report : \n " + this.toString());
            ex.printStackTrace();
        }

        return null;
    }

    @Override
    public String toString() {
        return "PinFailureReport{" +
                "appBundleId='" + appBundleId + '\'' +
                ", appVersion=" + appVersion +
                ", appVendorId='" + appVendorId + '\'' +
                ", appPlatform='" + appPlatform+ '\'' +
                ", trustKitVersion='" + trustKitVersion + '\'' +
                ", serverHostname='" + serverHostname + '\'' +
                ", port=" + port +
                ", notedHostname='" + notedHostname + '\'' +
                ", includeSubdomains=" + includeSubdomains +
                ", enforcePinning=" + enforcePinning +
                ", validatedCertificateChain=" + Arrays.toString(validatedCertificateChain) +
                ", dateTime=" + dateTime +
                ", knownPins=" + Arrays.toString(knownPins) +
                ", validationResult=" + validationResult +
                '}';
    }

    public static final class Builder {
        private String appBundleId;
        private String appVersion;
        private String appVendorId;
        private String appPlatform;
        private String trustKitVersion;
        private String hostname;
        private int port;
        private String notedHostname;
        private boolean includeSubdomains;
        private boolean enforcePinning;
        private String[] validatedCertificateChain;
        private Date dateTime;
        private String[] knownPins;
        private PinValidationResult validationResult;

        public Builder() {
        }

        public Builder appBundleId(String val) {
            appBundleId = val;
            return this;
        }

        public Builder appVersion(String val) {

            appVersion = val;
            return this;
        }

        public Builder appVendorId(String val) {
            appVendorId = val;
            return this;
        }

        public Builder appPlatform(String val) {
            appPlatform = val;
            return this;
        }

        public Builder trustKitVersion(String val) {
            trustKitVersion = val;
            return this;
        }

        public Builder hostname(String val) {
            hostname = val;
            return this;
        }

        public Builder port(int val) {
            port = val;
            return this;
        }

        public Builder notedHostname(String val) {
            notedHostname = val;
            return this;
        }

        public Builder includeSubdomains(boolean val) {
            includeSubdomains = val;
            return this;
        }

        public Builder enforcePinning(boolean val) {
            enforcePinning = val;
            return this;
        }

        public Builder validatedCertificateChain(String[] val) {
            validatedCertificateChain = val;
            return this;
        }

        public Builder dateTime(Date val) {
            dateTime = val;
            return this;
        }

        public Builder knownPins(String[] val) {
            knownPins = val;
            return this;
        }

        public Builder validationResult(PinValidationResult val) {
            validationResult = val;
            return this;
        }

        public PinFailureReport build() {
            return new PinFailureReport(this);
        }

    }


}
