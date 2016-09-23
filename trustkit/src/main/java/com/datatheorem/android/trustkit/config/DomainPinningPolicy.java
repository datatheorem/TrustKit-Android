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

import static java.net.IDN.toASCII;


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

    public DomainPinningPolicy(@NonNull String hostname,
                               boolean shouldIncludeSubdomains,
                               @NonNull Set<String> publicKeyHashStrList,
                               boolean shouldEnforcePinning,
                               @Nullable Date expirationDate,
                               @Nullable Set<String> reportUriStrList,
                               boolean shouldDisableDefaultReportUri)
            throws MalformedURLException {
        // Run some sanity checks on the configuration
        // Check if the hostname seems valid
        DomainValidator domainValidator = DomainValidator.getInstance(false);
        if (!domainValidator.isValid(hostname)) {
            throw new ConfigurationException("Tried to pin an invalid domain: " + hostname);
        }

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
        if (!shouldDisableDefaultReportUri) {
            reportUris.add(DEFAULT_REPORTING_URL);
        }

        this.hostname = hostname;
        this.shouldEnforcePinning = shouldEnforcePinning;
        this.shouldIncludeSubdomains = shouldIncludeSubdomains;
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
}
