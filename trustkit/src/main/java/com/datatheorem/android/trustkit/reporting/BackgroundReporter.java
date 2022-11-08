package com.datatheorem.android.trustkit.reporting;


import android.content.Context;
import android.content.Intent;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.pinning.PinningValidationResult;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;


public class BackgroundReporter {
    public static final String REPORT_VALIDATION_EVENT = "com.datatheorem.android.trustkit.reporting.BackgroundReporter:REPORT_VALIDATION_EVENT";
    public static final String EXTRA_REPORT = "Report";

    // App meta-data to be sent with the reports
    private final String appPackageName;
    private final String appVersion;
    private final String appVendorId;
    private final Context context;

    public BackgroundReporter(@NonNull Context context, @NonNull String appPackageName, @NonNull String appVersion,
                              @NonNull String appVendorId) {
        this.context = context;
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

    /**
     * Try to send a pin validation failure report to the reporting servers configured for the
     * hostname that triggered the failure.
     * <p>
     * Reports are rate-limited to one identical (same host, error and certificate chain) report
     * every 24 hours. Also and before Android N, only the default SSL validation is performed when
     * connecting to the reporting server (ie. no pinning validation).
     */
    @RequiresApi(api = 16)
    public void pinValidationFailed(@NonNull String serverHostname,
                                    @NonNull Integer serverPort,
                                    @NonNull List<X509Certificate> servedCertificateChain,
                                    @NonNull List<X509Certificate> validatedCertificateChain,
                                    @NonNull DomainPinningPolicy serverConfig,
                                    @NonNull PinningValidationResult validationResult) {

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
        PinningFailureReport report = new PinningFailureReport(appPackageName, appVersion,
                appVendorId, serverHostname, serverPort,
                serverConfig.getHostname(), serverConfig.shouldIncludeSubdomains(),
                serverConfig.shouldEnforcePinning(), servedCertificateChainAsPem,
                validatedCertificateChainAsPem, new Date(System.currentTimeMillis()),
                serverConfig.getPublicKeyPins(), validationResult);

        // If a similar report hasn't been sent recently, send it now
        if (!(ReportRateLimiter.shouldRateLimit(report))) {
            sendReport(report, serverConfig.getReportUris());
            broadcastReport(report);
        } else {
            TrustKitLog.i("Report for " + serverHostname + " was not sent due to rate-limiting");
        }
    }

    @RequiresApi(api = 16)
    protected void sendReport(@NonNull PinningFailureReport report,
                              @NonNull Set<URL> reportUriSet) {
        // Prepare the AsyncTask's arguments
        ArrayList<Object> taskParameters = new ArrayList<>();
        taskParameters.add(report);
        taskParameters.addAll(reportUriSet);
        // Call the task
        new BackgroundReporterTask().execute(taskParameters.toArray());
    }

    protected void broadcastReport(@NonNull PinningFailureReport report){
        Intent intent = new Intent(REPORT_VALIDATION_EVENT);
        intent.putExtra(EXTRA_REPORT, report);
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent);
    }
}
