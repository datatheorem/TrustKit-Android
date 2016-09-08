package com.datatheorem.android.trustkit.config;

import java.util.Arrays;

public final class PinnedDomainConfig {
    private String[] publicKeyHashes;
    private boolean enforcePinning;
    private String[] reportURIs;
    private boolean includeSubdomains;
    private boolean disableDefaultReportUri = false;

    private PinnedDomainConfig(Builder builder) {
        publicKeyHashes = builder.publicKeyHashes;
        enforcePinning = builder.enforcePinning;
        reportURIs = builder.reportURIs;
        includeSubdomains = builder.includeSubdomains;
        disableDefaultReportUri = builder.disableDefaultReportUri;
    }

    @Override
    public String toString() {
        return new StringBuilder()
                .append("PinnedDomainConfig{")
                .append("knownPins = " + Arrays.toString(publicKeyHashes) + "\n")
                .append("enforcePinning = " +enforcePinning + "\n")
                .append("reportUris = " + Arrays.toString(reportURIs) + "\n")
                .append("includeSubdomains = " + includeSubdomains + "\n")
                .append("disableDefaultReportuUri = " + disableDefaultReportUri+"\n")
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

        public PinnedDomainConfig build() {
            return new PinnedDomainConfig(this);
        }
    }

    public String[] getPublicKeyHashes() {
        return publicKeyHashes;
    }

    public boolean isEnforcePinning() {
        return enforcePinning;
    }

    public String[] getReportURIs() {
        return reportURIs;
    }

    public boolean isIncludeSubdomains() {
        return includeSubdomains;
    }
}
