package com.datatheorem.android.trustkit.reporting;


import android.os.AsyncTask;
import android.util.Base64;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;


/**
 * The BackgroundReporter save a report when a pinning validation fail and send the report
 * to the specific URI.
 */
public class BackgroundReporter {
    // Main application environment information
    private final String appPackageName;
    private final String appVersion;
    private final String appVendorId;

    // Configuration and Objects managing all the operation done by the BackgroundReporter
    private final boolean shouldRateLimitsReports;

    // TODO(ad): Using a single reportSender will create a race-condition when multiple threads try
    // to send reports at the same time: the response code in reportSender will be overriden.
    // Fix this.
    private final PinFailureReportHttpSender reportSender;


    public BackgroundReporter(boolean shouldRateLimitsReports, String appPackageName,
                              String appVersion, String appVendorId) {
        this.shouldRateLimitsReports = shouldRateLimitsReports;
        this.reportSender = new PinFailureReportHttpSender();
        this.appPackageName = appPackageName;
        this.appVersion = appVersion;
        this.appVendorId = appVendorId;
    }

    private static String certificateToPem(X509Certificate certificate) {
        byte[] certificateData;
        try {
            certificateData = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Should never happen - certificate was previously " +
                    "parsed by the system");
        }

        // Create the PEM string
        String certificateAsPem = "-----BEGIN CERTIFICATE-----\n";
        certificateAsPem += Base64.encodeToString(certificateData, Base64.DEFAULT);
        certificateAsPem += "-----END CERTIFICATE-----\n";
        return certificateAsPem;
    }


    public void pinValidationFailed(String serverHostname,
                                    Integer serverPort,
                                    List<X509Certificate> servedCertificateChain,
                                    List<X509Certificate> validatedCertificateChain,
                                    PinnedDomainConfiguration serverConfig,
                                    PinValidationResult validationResult) {

        TrustKitLog.i("Generating pin failure report for " + serverHostname);

        // Convert the certificates to PEM strings
        ArrayList<String> validatedCertificateChainAsPem = new ArrayList<>();
        for (X509Certificate certificate : validatedCertificateChain) {
            validatedCertificateChainAsPem.add(certificateToPem(certificate));
        }
        ArrayList<String> servedCertificateChainAsPem = new ArrayList<>();
        for (X509Certificate certificate : servedCertificateChain) {
            servedCertificateChainAsPem.add(certificateToPem(certificate));
        }

        // Generate the corresponding pin failure report
        final PinFailureReport report = new PinFailureReport(appPackageName, appVersion,
                appVendorId, BuildConfig.VERSION_NAME, serverHostname, serverPort,
                serverConfig.getNotedHostname(), serverConfig.shouldIncludeSubdomains(),
                serverConfig.shouldEnforcePinning(), servedCertificateChainAsPem,
                validatedCertificateChainAsPem, new Date(System.currentTimeMillis()),
                serverConfig.getPublicKeyHashes(), validationResult);

        // If a similar report hasn't been sent recently, send it now
        if (shouldRateLimitsReports && ReportsRateLimiter.shouldRateLimit(report)) {
            TrustKitLog.i("Pin failure report for " + serverHostname
                    + " was not sent due to rate-limiting");
            return;
        }

        final HashSet<URL> reportUriSet = (HashSet<URL>) serverConfig.getReportUris();
        new AsyncTask<HashSet<URL>, Void, Void>() {
            @SafeVarargs
            @Override
            protected final Void doInBackground(HashSet<URL>... params) {
                for (final URL reportUri : reportUriSet) {
                    reportSender.send(reportUri, report);
                }
                return null;
            }

            @Override
            protected void onPostExecute(Void aVoid) {
                if (reportSender.getResponseCode() >= 200 && reportSender.getResponseCode() < 300) {
                    TrustKitLog.i("Background upload - task completed successfully: pinning " +
                            "failure report sent");
                } else {
                    TrustKitLog.e("Background upload - task completed with error: connection" +
                            " error");
                }
            }

        }.execute(reportUriSet);
    }
}
