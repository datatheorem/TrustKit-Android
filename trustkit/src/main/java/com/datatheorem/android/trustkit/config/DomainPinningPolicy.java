package com.datatheorem.android.trustkit.config;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
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
    @NonNull private final Set<PublicKeyPin> publicKeyPins;
    @Nullable private final Date expirationDate;
    private final boolean shouldEnforcePinning;
    @NonNull private final Set<URL> reportUris;

    DomainPinningPolicy(@NonNull String hostname,
                        Boolean shouldIncludeSubdomains,
                        Set<String> publicKeyHashStrList,
                        Boolean shouldEnforcePinning,
                        @Nullable Date expirationDate,
                        @Nullable Set<String> reportUriStrList,
                        Boolean shouldDisableDefaultReportUri)
            throws MalformedURLException {
        // Run some sanity checks on the configuration
        // Check if the hostname seems valid
        DomainValidator domainValidator = DomainValidator.getInstance();
        if (!domainValidator.isValid(hostname)) {
            throw new ConfigurationException("Tried to pin an invalid domain: " + hostname);
        }
        this.hostname = hostname.trim();

        // Due to the fact some configurations could be added without any pin (e.g. localhost)
        // the publicKeyHashStrList would be null.
        // Thus we're managing these cases as an empty set of pins.
        if (publicKeyHashStrList == null)
            publicKeyHashStrList = new HashSet<>();

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


        // Check if the configuration has a empty pin-set and still would enforce pinning
        // TrustKit should not work if the configuration contains both (opposite behaviors)
        if (publicKeyHashStrList.isEmpty() && this.shouldEnforcePinning) {
            throw new ConfigurationException("An empty pin-set was supplied "+
              "for domain " + this.hostname + " with the enforcePinning set to true. " +
              "An empty pin-set disables pinning and can't be use with enforcePinning set to true.");
        }

        // Check if the configuration has at least two pins (including a backup pin)
        // TrustKit should not work if the configuration contains only one pin
        // more info (https://tools.ietf.org/html/rfc7469#page-21)
        if (publicKeyHashStrList.size() < 2 && this.shouldEnforcePinning) {
            throw new ConfigurationException("Less than two pins were supplied "+
                    "for domain " + this.hostname + ". This might " +
                    "brick your App; please review the Getting Started guide in " +
                    "./docs/getting-started.md");
        }

        // Parse the supplied pins
        publicKeyPins = new HashSet<>();
        for (String pinStr : publicKeyHashStrList)  {
            publicKeyPins.add(new PublicKeyPin(pinStr));
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

        this.expirationDate = expirationDate;
    }

    @NonNull
    public String getHostname() {
        return hostname;
    }

    @NonNull
    public Set<PublicKeyPin> getPublicKeyPins() {
        return publicKeyPins;
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

    @NonNull
    @Override
    public String toString() {
        return "DomainPinningPolicy{" +
                "hostname = " + hostname + "\n" +
                "knownPins = " + Arrays.toString(publicKeyPins.toArray()) +
                "\n" +
                "shouldEnforcePinning = " + shouldEnforcePinning + "\n" +
                "reportUris = " + reportUris + "\n" +
                "shouldIncludeSubdomains = " + shouldIncludeSubdomains + "\n" +
                "}";
    }


    public static final class Builder {
        // The domain must always be specified in domain-config
        private String hostname;

        // The remaining settings can be inherited from a parent domain-config
        private Boolean shouldIncludeSubdomains;
        private Set<String> publicKeyHashes;
        private Date expirationDate;
        private Boolean shouldEnforcePinning;
        private Set<String> reportUris;
        private Boolean shouldDisableDefaultReportUri;

        // The parent domain-config
        private Builder parentBuilder = null;

        @Nullable
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

            if (publicKeyHashes == null) {
                // This configuration entry is not for pinning but something else; skip it
                return null;
            }
            return new DomainPinningPolicy(
                    hostname,
                    shouldIncludeSubdomains,
                    publicKeyHashes,
                    shouldEnforcePinning,
                    expirationDate,
                    reportUris,
                    shouldDisableDefaultReportUri
            );
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

        public Builder setHostname(String hostname) {
            this.hostname = hostname;
            return this;
        }

        Boolean getShouldIncludeSubdomains() {
            return shouldIncludeSubdomains;
        }

        public Builder setShouldIncludeSubdomains(Boolean shouldIncludeSubdomains) {
            this.shouldIncludeSubdomains = shouldIncludeSubdomains;
            return this;
        }

        Set<String> getPublicKeyHashes() {
            return publicKeyHashes;
        }

        public Builder setPublicKeyHashes(Set<String> publicKeyHashes) {
            this.publicKeyHashes = publicKeyHashes;
            return this;
        }

        Date getExpirationDate() {
            return expirationDate;
        }

        public Builder setExpirationDate(Date expirationDate) {
            this.expirationDate = expirationDate;
            return this;
        }

        Boolean getShouldEnforcePinning() {
            return shouldEnforcePinning;
        }

        public Builder setShouldEnforcePinning(Boolean shouldEnforcePinning) {
            this.shouldEnforcePinning = shouldEnforcePinning;
            return this;
        }

        Set<String> getReportUris() {
            return reportUris;
        }

        public Builder setReportUris(Set<String> reportUris) {
            this.reportUris = reportUris;
            return this;
        }

        Boolean getShouldDisableDefaultReportUri() {
            return shouldDisableDefaultReportUri;
        }

        public Builder setShouldDisableDefaultReportUri(Boolean shouldDisableDefaultReportUri) {
            this.shouldDisableDefaultReportUri = shouldDisableDefaultReportUri;
            return this;
        }
    }
}
