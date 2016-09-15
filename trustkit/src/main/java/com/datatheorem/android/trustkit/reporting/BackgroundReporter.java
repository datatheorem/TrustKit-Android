package com.datatheorem.android.trustkit.reporting;


import android.os.AsyncTask;
import android.util.Base64;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.net.URL;
import java.security.cert.Certificate;
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
public final class BackgroundReporter {
    private static final String APP_PLATFORM = "ANDROID";

    // Main application environment information
    private final String appPackageName;
    private final String appVersion;
    private final String appVendorId;

    // Configuration and Objects managing all the operation done by the BackgroundReporter
    private final boolean shouldRateLimitsReports;
    private final PinFailureReportHttpSender pinFailureReportHttpSender;


    public BackgroundReporter(boolean shouldRateLimitsReports, String appPackageName,
                              String appVersion, String appVendorId) {
        this.shouldRateLimitsReports = shouldRateLimitsReports;
        this.pinFailureReportHttpSender = new PinFailureReportHttpSender();
        this.appPackageName = appPackageName;
        this.appVersion = appVersion;
        this.appVendorId = appVendorId;
    }

    private String certificateToPem(X509Certificate certificate) {
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


    public void pinValidationFailed(String serverHostname, Integer serverPort,
                                    List<X509Certificate> servedCertificateChain,
                                          List<X509Certificate> validatedCertificateChain,
                                          String notedHostname,
                                          PinnedDomainConfiguration serverConfig,
                                          PinValidationResult validationResult) {

        TrustKitLog.i("Generating pin failure report for " + serverHostname);
        // TODO(ad): Also send the validated chain
        // Convert the certificates to PEM strings
        ArrayList<String> certificateChainAsPem = new ArrayList<>();
        for (Certificate certificate : servedCertificateChain) {
            certificateChainAsPem.add(certificateToPem(certificate));
        }

        // Generate the corresponding pin failure report
        final PinFailureReport report = new PinFailureReport.Builder()
                .appBundleId(appPackageName)
                .appVersion(appVersion)
                .appPlatform(APP_PLATFORM)
                .appVendorId(appVendorId)
                .trustKitVersion(BuildConfig.VERSION_NAME)
                .hostname(serverHostname)
                .port(serverPort)
                .dateTime(new Date(System.currentTimeMillis()))
                .notedHostname(serverConfig.getNotedHostname())
                .includeSubdomains(serverConfig.isIncludeSubdomains())
                .enforcePinning(serverConfig.isEnforcePinning())
                .validatedCertificateChain((String[]) certificateChainAsPem.toArray())
                .knownPins(serverConfig.getPublicKeyHashes())
                .validationResult(validationResult).build();

        // If a similar report hasn't been sent recently, send it now
        if (shouldRateLimitsReports && ReportsRateLimiter.shouldRateLimit(report)) {
            TrustKitLog.i("Pin failure report for " + serverHostname
                    + " was not sent due to rate-limiting");
            return;
        }

        final HashSet<URL> reportUriSet = serverConfig.getReportURIs();
        new AsyncTask() {
            @Override
            protected Object doInBackground(Object[] params) {
                for (final URL reportUri : reportUriSet) {
                    pinFailureReportHttpSender.send(reportUri, report);
                }
                return null;
            }

            @Override
            protected void onPostExecute(Object o) {
                if (pinFailureReportHttpSender.getResponseCode() >= 200
                        && pinFailureReportHttpSender.getResponseCode() < 300) {
                    TrustKitLog.i("Background upload - task completed successfully: pinning " +
                            "failure report sent");
                } else {
                    TrustKitLog.e("Background upload - task completed with error: connection" +
                            " error");
                }
            }
        }.execute();
    }
}
