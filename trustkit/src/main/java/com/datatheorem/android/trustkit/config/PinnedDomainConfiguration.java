package com.datatheorem.android.trustkit.config;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
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

    private final String[] publicKeyHashes; // TODO(ad): Convert this to a set: faster to check if an element is in it and gets rid of duplicates
    private final boolean enforcePinning;
    private final HashSet<URL> reportURIs;
    private final boolean includeSubdomains;

    private PinnedDomainConfiguration(Builder builder) {
        // TODO(ad): Require two pins minimum and do some sanity check on them (length, etc.)
        publicKeyHashes = builder.publicKeyHashes;

        enforcePinning = builder.enforcePinning;
        includeSubdomains = builder.includeSubdomains;

        // Create the final list of report URIs
        // Add the default report URI if enabled
        reportURIs = new HashSet<URL>();
        if (!builder.disableDefaultReportUri) {
            reportURIs.add(DEFAULT_REPORTING_URL);
        }
        // Add the supplied report URIs
        if (builder.reportURIs != null) {
            for (String url: builder.reportURIs) {
                try {
                    URL parsedUrl = new URL(url);
                    reportURIs.add(parsedUrl);
                } catch (MalformedURLException e) {
                    throw new IllegalArgumentException("Could not parse supplied URL: " + url);
                }
            }
        }
    }

    @Override
    public String toString() {
        return new StringBuilder()
                .append("PinnedDomainConfiguration{")
                .append("knownPins = " + Arrays.toString(publicKeyHashes) + "\n")
                .append("enforcePinning = " +enforcePinning + "\n")
                .append("reportUris = " + reportURIs + "\n")
                .append("includeSubdomains = " + includeSubdomains + "\n")
                .append("}")
                .toString();
    }

    public static final class Builder {
        private String[] publicKeyHashes;
        private boolean enforcePinning;
        private String[] reportURIs;
        private boolean includeSubdomains;
        private boolean disableDefaultReportUri;

        public Builder() {
        }

        public Builder publicKeyHashes(String[] val) {
            publicKeyHashes = val;
            return this;
        }

        public Builder enforcePinning(boolean val) {
            enforcePinning = val;
            return this;
        }

        public Builder reportURIs(String[] val) {
            reportURIs = val;
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

        public PinnedDomainConfiguration build() {
            return new PinnedDomainConfiguration(this);
        }
    }

    public String[] getPublicKeyHashes() {
        return publicKeyHashes;
    }

    public boolean isEnforcePinning() {
        return enforcePinning;
    }

    public HashSet<URL> getReportURIs() {
        return reportURIs;
    }

    public boolean isIncludeSubdomains() {
        return includeSubdomains;
    }
}
