package com.datatheorem.android.trustkit.config;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.datatheorem.android.trustkit.pinning.PublicKeyPin;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;


public final class DomainPinningPolicy {

    // The default URL to submit pin failure report to
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

    @NonNull private final String hostname;
    private final boolean shouldIncludeSubdomains;
    @NonNull private final Set<PublicKeyPin> publicKeyHashes;
    @Nullable private final Date expirationDate;
    private final boolean shouldEnforcePinning;
    @NonNull private final Set<URL> reportUris;

    DomainPinningPolicy(@NonNull String hostname,
                        Boolean shouldIncludeSubdomains,
                        @NonNull Set<String> publicKeyHashStrList,
                        Boolean shouldEnforcePinning,
                        @Nullable Date expirationDate,
                        @Nullable Set<String> reportUriStrList,
                        Boolean shouldDisableDefaultReportUri)
            throws MalformedURLException {
        // Run some sanity checks on the configuration
        // Check if the hostname seems valid
        DomainValidator domainValidator = DomainValidator.getInstance(false);
        if (!domainValidator.isValid(hostname)) {
            throw new ConfigurationException("Tried to pin an invalid domain: " + hostname);
        }
        this.hostname = hostname;

        // Check if the configuration has at least two pins (including a backup pin)
        // TrustKit should not work if the configuration contains only one pin
        // more info (https://tools.ietf.org/html/rfc7469#page-21)
        if (publicKeyHashStrList.size() < 2) {
            // TODO(ad): Once we've written the documentation, encore that this error is still valid
            throw new ConfigurationException("Less than two pins were supplied "+
                    "for domain " + hostname + ". This might " +
                    "brick your App; please review the Getting Started guide in " +
                    "./docs/getting-started.md");
        }

        // Parse the supplied pins
        publicKeyHashes = new HashSet<>();
        for (String pinStr : publicKeyHashStrList)  {
            publicKeyHashes.add(new PublicKeyPin(pinStr));
        }

        // Parse the supplied report URLs
        reportUris = new HashSet<>();
        if (reportUriStrList != null) {
            for (String UriStr : reportUriStrList) {
                reportUris.add(new URL(UriStr));
            }
        }

        // Add the default report URL
        if ((shouldDisableDefaultReportUri == null) || (!shouldDisableDefaultReportUri) ) {
            reportUris.add(DEFAULT_REPORTING_URL);
        }

        // Parse boolean settings and handle default values
        if (shouldEnforcePinning == null) {
            this.shouldEnforcePinning = false;
        } else {
            this.shouldEnforcePinning = shouldEnforcePinning;
        }
        if (shouldIncludeSubdomains == null) {
            this.shouldIncludeSubdomains = false;
        } else {
            this.shouldIncludeSubdomains = shouldIncludeSubdomains;
        }

        this.expirationDate = expirationDate;
    }

    @NonNull
    public String getHostname() {
        return hostname;
    }

    @NonNull
    public Set<PublicKeyPin> getPublicKeyHashes() {
        return publicKeyHashes;
    }

    public boolean shouldEnforcePinning() {
        return shouldEnforcePinning;
    }

    @NonNull
    public Set<URL> getReportUris() {
        return reportUris;
    }

    public boolean shouldIncludeSubdomains() {
        return shouldIncludeSubdomains;
    }

    @Nullable
    public Date getExpirationDate() {
        return expirationDate;
    }

    @Override
    public String toString() {
        return new StringBuilder()
                .append("DomainPinningPolicy{")
                .append("hostname = ").append(hostname).append("\n")
                .append("knownPins = ").append(Arrays.toString(publicKeyHashes.toArray()))
                .append("\n")
                .append("shouldEnforcePinning = ").append(shouldEnforcePinning).append("\n")
                .append("reportUris = ").append(reportUris).append("\n")
                .append("shouldIncludeSubdomains = ").append(shouldIncludeSubdomains).append("\n")
                .append("}")
                .toString();
    }


    public static final class Builder {
        // The domain must always be specified in domain-config
        private String hostname;

        // The remaining settings can be inherited from a parent domain-config
        private Boolean shouldIncludeSubdomains = null;
        private Set<String> publicKeyHashes = null;
        private Date expirationDate = null;
        private Boolean shouldEnforcePinning = null;
        private Set<String> reportUris = null;
        private Boolean shouldDisableDefaultReportUri = null;

        // The parent domain-config
        private Builder parentBuilder = null;

        public DomainPinningPolicy build() throws MalformedURLException {

            if (parentBuilder != null) {
                // Get missing values from the parent as some entries can be inherited
                // build() should already have been called on it so it has its parent's values
                // inherited already
                if (shouldIncludeSubdomains == null) {
                    shouldIncludeSubdomains = parentBuilder.getShouldIncludeSubdomains();
                }

                if (publicKeyHashes == null) {
                    publicKeyHashes = parentBuilder.getPublicKeyHashes();
                }

                if (expirationDate == null) {
                    expirationDate = parentBuilder.getExpirationDate();
                }

                if (shouldEnforcePinning == null) {
                    shouldEnforcePinning = parentBuilder.getShouldEnforcePinning();
                }

                if (reportUris == null) {
                    reportUris = parentBuilder.getReportUris();
                }

                if (shouldDisableDefaultReportUri == null) {
                    shouldDisableDefaultReportUri = parentBuilder.getShouldDisableDefaultReportUri();
                }
            }

            return new DomainPinningPolicy(hostname, shouldIncludeSubdomains, publicKeyHashes,
                    shouldEnforcePinning, expirationDate, reportUris,
                    shouldDisableDefaultReportUri);
        }

        public Builder setParent(Builder parent) {
            // Sanity check to avoid adding loops.
            Builder current = parent;
            while (current != null) {
                if (current == this) {
                    throw new IllegalArgumentException("Loops are not allowed in Builder parents");
                }
                current = current.parentBuilder;
            }
            parentBuilder = parent;
            return this;
        }

        public void setHostname(String hostname) {
            this.hostname = hostname;
        }

        Boolean getShouldIncludeSubdomains() {
            return shouldIncludeSubdomains;
        }

        public void setShouldIncludeSubdomains(Boolean shouldIncludeSubdomains) {
            this.shouldIncludeSubdomains = shouldIncludeSubdomains;
        }

        Set<String> getPublicKeyHashes() {
            return publicKeyHashes;
        }

        public void setPublicKeyHashes(Set<String> publicKeyHashes) {
            this.publicKeyHashes = publicKeyHashes;
        }

        Date getExpirationDate() {
            return expirationDate;
        }

        public void setExpirationDate(Date expirationDate) {
            this.expirationDate = expirationDate;
        }

        Boolean getShouldEnforcePinning() {
            return shouldEnforcePinning;
        }

        public void setShouldEnforcePinning(Boolean shouldEnforcePinning) {
            this.shouldEnforcePinning = shouldEnforcePinning;
        }

        Set<String> getReportUris() {
            return reportUris;
        }

        public void setReportUris(Set<String> reportUris) {
            this.reportUris = reportUris;
        }

        Boolean getShouldDisableDefaultReportUri() {
            return shouldDisableDefaultReportUri;
        }

        public void setShouldDisableDefaultReportUri(Boolean shouldDisableDefaultReportUri) {
            this.shouldDisableDefaultReportUri = shouldDisableDefaultReportUri;
        }
    }
}