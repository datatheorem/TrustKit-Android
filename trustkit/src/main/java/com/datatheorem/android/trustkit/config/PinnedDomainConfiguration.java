package com.datatheorem.android.trustkit.config;

import android.support.annotation.NonNull;

import com.datatheorem.android.trustkit.pinning.SubjectPublicKeyInfoPin;
import com.google.common.net.InternetDomainName;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.Set;


public final class PinnedDomainConfiguration {


    private final Set<SubjectPublicKeyInfoPin> publicKeyHashes;
    private final boolean shouldEnforcePinning;
    private final Set<URL> reportURIs;
    private final boolean shouldIncludeSubdomains;
    private final String notedHostname;
    private final Date expirationDate;

    private PinnedDomainConfiguration(Builder builder) {
        notedHostname = builder.pinnedDomainName;
        publicKeyHashes = builder.publicKeyHashes;
        shouldEnforcePinning = builder.shouldEnforcePinning;
        shouldIncludeSubdomains = builder.shouldIncludeSubdomains;
        expirationDate = builder.expirationDate;
        reportURIs = builder.reportURIs;
    }

    public String getNotedHostname() {
        return notedHostname;
    }

    public Set<SubjectPublicKeyInfoPin> getPublicKeyHashes() {
        return publicKeyHashes;
    }

    public boolean shouldEnforcePinning() {
        return shouldEnforcePinning;
    }

    public Set<URL> getReportURIs() {
        return reportURIs;
    }

    public boolean shouldIncludeSubdomains() {
        return shouldIncludeSubdomains;
    }

    @Override
    public String toString() {
        return new StringBuilder()
                .append("PinnedDomainConfiguration{")
                .append("notedHostname = ").append(notedHostname).append("\n")
                .append("knownPins = ").append(Arrays.toString(publicKeyHashes.toArray()))
                .append("\n")
                .append("shouldEnforcePinning = ").append(shouldEnforcePinning).append("\n")
                .append("reportUris = ").append(reportURIs).append("\n")
                .append("shouldIncludeSubdomains = ").append(shouldIncludeSubdomains).append("\n")
                .append("}")
                .toString();
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public static final class Builder {
        private String pinnedDomainName;
        private Set<SubjectPublicKeyInfoPin> publicKeyHashes;
        private boolean shouldEnforcePinning;
        private Set<URL> reportURIs;
        private boolean shouldIncludeSubdomains;
        private Date expirationDate;

        public Builder() {
        }

        public Builder pinnedDomainName(@NonNull String val) {
            pinnedDomainName = val;
            return this;
        }

        public Builder publicKeyHashes(@NonNull Set<SubjectPublicKeyInfoPin> val) {
            publicKeyHashes = val;
            return this;
        }

        public Builder shouldEnforcePinning(boolean val) {
            shouldEnforcePinning = val;
            return this;
        }

        public Builder reportUris(@NonNull Set<URL> val) {
            reportURIs = val;
            return this;
        }

        public Builder shouldIncludeSubdomains(boolean val) {
            shouldIncludeSubdomains = val;
            return this;
        }

        public Builder expirationDate(Date date) throws ParseException {

            expirationDate = date;
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
                    && shouldIncludeSubdomains){
                throw new ConfigurationException("TrustKit was initialized with shouldIncludeSubdomains "+
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

            return new PinnedDomainConfiguration(this);
        }
    }
}
