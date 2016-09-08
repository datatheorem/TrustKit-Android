package com.datatheorem.android.trustkit.report;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.AsyncTask;
import android.preference.PreferenceManager;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Date;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.UUID;


/**
 * The BackgroundReporter save a report when a pinning validation fail and send the report
 * to the specific URI.
 */
public final class BackgroundReporter {
    private static final String TRUSTKIT_VENDOR_ID = "TRUSTKIT_VENDOR_ID";
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

    private static final String appPlatform = "ANDROID";

    // Main application environment information
    private String appPackageName;
    private String appVersion;
    private String appVendorId;

    // Configuration and Objects managing all the operation done by the BackgroundReporter
    private boolean shouldRateLimitsReports;
    private final PinFailureReportHttpSender pinFailureReportHttpSender;
    private final PinFailureReportInternalSender pinFailureReportInternalSender;


    public BackgroundReporter(boolean shouldRateLimitsReports, String broadcastIdentifier) {
        Context appContext = TrustKit.getInstance().getAppContext();
        this.shouldRateLimitsReports = shouldRateLimitsReports;
        this.pinFailureReportHttpSender = new PinFailureReportHttpSender();
        this.pinFailureReportInternalSender = new PinFailureReportInternalSender(appContext,
                broadcastIdentifier);

        this.appPackageName = appContext.getPackageName();

        try {
            this.appVersion =
                    appContext.getPackageManager().getPackageInfo(appPackageName, 0).versionName;

        } catch (PackageManager.NameNotFoundException e) {
            this.appVersion = "N/A";
        }

        SharedPreferences trustKitSharedPreferences =
                PreferenceManager.getDefaultSharedPreferences(appContext);
        String appVendorId = trustKitSharedPreferences.getString(TRUSTKIT_VENDOR_ID, "");
        if (!appVendorId.equals("")) {
            this.appVendorId = appVendorId;
        } else {
            this.appVendorId = UUID.randomUUID().toString();
            SharedPreferences.Editor editor = trustKitSharedPreferences.edit();
            editor.putString(TRUSTKIT_VENDOR_ID, this.appVendorId);
            editor.apply();
        }
        DEFAULT_REPORTING_URL = new URL(DEFAULT_REPORTING_URL_STRING);
    }

    /**
     * Create a {@link PinFailureReport PinFailureReport}, save it using a
     * {@link PinFailureReportDiskStore} instance and send it using
     * a {@link PinFailureReportHttpSender} instance.
     * @param serverHostname
     * @param serverPort
     * @param certificateChain
     * @param notedHostname
     * @param reportURIs
     * @param disableDefaultReportUri
     *@param includeSubdomains
     * @param enforcePinning
     * @param knownPins
     * @param validationResult     @throws NullPointerException
     * @throws IOException
     */
    public final void pinValidationFailed(String serverHostname, Integer serverPort,
                                          String[] certificateChain, String notedHostname,
                                          URL[] reportURIs,
                                          boolean disableDefaultReportUri,
                                          boolean includeSubdomains, boolean enforcePinning,
                                          String[] knownPins, PinValidationResult validationResult){

        final ArrayList<URL> finalReportUris = new ArrayList<>();

        if (!disableDefaultReportUri) {
            finalReportUris.add(DEFAULT_REPORTING_URL);
        } else {
            if (reportURIs == null) {
                throw new NullPointerException("BackgroundReporter configuration invalid. Reporter"+
                        " was given an invalid value for reportURIs: null for domain " +
                        notedHostname);
            } else {
                finalReportUris.addAll(Arrays.asList(reportURIs));
            }
        }

        final PinFailureReport report = new PinFailureReport.Builder()
                .appBundleId(appPackageName)
                .appVersion(appVersion)
                .appPlatform(appPlatform)
                .appVendorId(appVendorId)
                .trustKitVersion(BuildConfig.VERSION_NAME)
                .hostname(serverHostname)
                .port(serverPort)
                .dateTime(new Date(System.currentTimeMillis()))
                .notedHostname(notedHostname)
                .includeSubdomains(includeSubdomains)
                .enforcePinning(enforcePinning)
                .validatedCertificateChain(certificateChain)
                .knownPins(knownPins)
                .validationResult(validationResult).build();

        if (shouldRateLimitsReports && ReportsRateLimiter.shouldRateLimit(report)) {
            TrustKitLog.i("Pin failure report for " + serverHostname
                    + " was not sent due to rate-limiting");
            return;
        }


        new AsyncTask() {
            @Override
            protected Object doInBackground(Object[] params) {

                for (final URL reportURI : finalReportUris) {
                    pinFailureReportHttpSender.send(reportURI, report);
                }

                // Send a notification to the App
                pinFailureReportInternalSender.send(report);
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
