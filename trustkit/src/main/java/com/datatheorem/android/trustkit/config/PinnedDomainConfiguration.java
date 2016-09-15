package com.datatheorem.android.trustkit.config;

import android.support.annotation.NonNull;

import com.datatheorem.android.trustkit.pinning.SubjectPublicKeyInfoPin;
import com.google.common.net.InternetDomainName;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;


public final class PinnedDomainConfiguration {
    private static final URL DEFAULT_REPORTING_URL;
    static {
        java.net.URL defaultUrl;
        try {
            defaultUrl = new java.net.URL("https://overmind.datatheorem.com/trustkit/report");
        } catch (java.net.MalformedURLException e) {
            throw new IllegalStateException("Bad DEFAULT_REPORTING_URL");
        }
        DEFAULT_REPORTING_URL = defaultUrl;
    }

    private final Set<SubjectPublicKeyInfoPin> publicKeyHashes;
    private final boolean enforcePinning;
    private final Set<URL> reportURIs;
    private final boolean includeSubdomains;
    private final String notedHostname;

    private PinnedDomainConfiguration(Builder builder) {
        notedHostname = builder.pinnedDomainName;
        publicKeyHashes = builder.publicKeyInfoPins;
        enforcePinning = builder.enforcePinning;
        includeSubdomains = builder.includeSubdomains;

        // Create the final list of report URIs
        // Add the default report URI if enabled
        reportURIs = new HashSet<>();
        if (!builder.disableDefaultReportUri) {
            reportURIs.add(DEFAULT_REPORTING_URL);
        }
        // Add the supplied report URIs
        if (builder.reportURIs != null) {
            reportURIs.addAll(builder.reportURIs);
        }
    }

    public String getNotedHostname() {
        return notedHostname;
    }

    public Set<SubjectPublicKeyInfoPin> getPublicKeyHashes() {
        return publicKeyHashes;
    }

    // TODO(ad): Rename this to shouldEnforcePinning()
    public boolean isEnforcePinning() {
        return enforcePinning;
    }

    public Set<URL> getReportURIs() {
        return reportURIs;
    }

    public boolean isIncludeSubdomains() {
        return includeSubdomains;
    }

    @Override
    public String toString() {
        return new StringBuilder()
                .append("PinnedDomainConfiguration{")
                .append("notedHostname = " + notedHostname + "\n")
                .append("knownPins = " + Arrays.toString(publicKeyHashes.toArray()) + "\n")
                .append("enforcePinning = " +enforcePinning + "\n")
                .append("reportUris = " + reportURIs + "\n")
                .append("includeSubdomains = " + includeSubdomains + "\n")
                .append("}")
                .toString();
    }

    public static final class Builder {
        private String pinnedDomainName;
        private Set<String> publicKeyHashes;
        private Set<SubjectPublicKeyInfoPin> publicKeyInfoPins;
        private boolean enforcePinning;
        private Set<URL> reportURIs;
        private boolean includeSubdomains;
        private boolean disableDefaultReportUri;

        public Builder() {
        }

        public Builder pinnedDomainName(@NonNull String val) {
            pinnedDomainName = val;
            return this;
        }

        public Builder publicKeyHashes(@NonNull Set<String> val) {
            publicKeyHashes = val;
            return this;
        }

        public Builder enforcePinning(boolean val) {
            enforcePinning = val;
            return this;
        }

        public Builder reportURIs(@NonNull String[] val) {
            reportURIs = new HashSet<>();
            for (String url : val) {
                try {
                    reportURIs.add(new URL(url));
                } catch (MalformedURLException e) {
                    throw new ConfigurationException("Malformed url for reportUrl " + url);
                }
            }
            return this;
        }

        public Builder includeSubdomains(boolean val) {
            includeSubdomains = val;
            return this;
        }

        public Builder disableDefaultReportUri(boolean val) {
            disableDefaultReportUri = val;
            return this;
        }

        /*
            All sanity checks run during the build() method preventing any bad configuration to be
            added to the main configuration.
         */
        public PinnedDomainConfiguration build() {
            // Check if a pinned domain is present
            if (pinnedDomainName == null || pinnedDomainName.equals("")) {
                throw new ConfigurationException("TrustKit was initialized with no pinned domain.");
            }

            // Check if the pinned domain is well formatted
            try {
                pinnedDomainName.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new ConfigurationException("TrustKit was initialized with an invalid domain");
            }

            // Check if the pinned domain is valid:
            // TrustKit should not work if the configuration asks to pin connections for subdomains
            // for *.com and other TLDs
            if (InternetDomainName.from(pinnedDomainName).isPublicSuffix()
                    && !InternetDomainName.isValid(pinnedDomainName)
                    && includeSubdomains){
                throw new ConfigurationException("TrustKit was initialized with includeSubdomains "+
                        "for a domain suffix " + InternetDomainName.from(pinnedDomainName));
            }

            // Check if the configuration has at least two pins
            // TrustKit should not work if the configuration contains only one pin
            // more info (https://tools.ietf.org/html/rfc7469#page-21)
            if (publicKeyHashes.size() < 2) {
                throw new ConfigurationException("TrustKit was initialized with less than two pins"+
                        ", (ie. no backup pins for domain " + pinnedDomainName + ". This might " +
                        "brick your App; please review the Getting Started guide in " +
                        "./docs/getting-started.md");
            }

            publicKeyInfoPins = new HashSet<>(publicKeyHashes.size());
            for (String publicKeyHash : publicKeyHashes) {
                publicKeyInfoPins.add(new SubjectPublicKeyInfoPin(publicKeyHash));
            }

            return new PinnedDomainConfiguration(this);
        }
    }
}
