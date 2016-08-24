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
import java.util.UUID;


/**
 * The BackgroundReporter save a report when a pinning validation fail and send the report
 * to the specific URI.
 */
public final class BackgroundReporter{

    private final String APP_VENDOR_ID_LABEL = "APP_VENDOR_ID";

    // Main application environment information
    private String appPackageName;
    private String appVersion;
    private String appVendorId;
    private String appPlatform;

    // Configuration and Objects managing all the operation done by the BackgroundReporter
    private boolean shouldRateLimitsReports;
    private final PinFailureReportDiskStore pinFailureReportDiskStore;
    private final PinFailureReportHttpSender pinFailureReportHttpSender;
    private final PinFailureReportInternalSender pinFailureReportInternalSender;



    public BackgroundReporter(boolean shouldRateLimitsReports, String broadcastIdentifier) {
        Context appContext = TrustKit.getInstance().getAppContext();
        this.shouldRateLimitsReports = shouldRateLimitsReports;
        this.pinFailureReportDiskStore = new PinFailureReportDiskStore(appContext);
        this.pinFailureReportHttpSender = new PinFailureReportHttpSender();
        this.pinFailureReportInternalSender = new PinFailureReportInternalSender(appContext,
                broadcastIdentifier);


        this.appPlatform = "ANDROID";
        this.appPackageName = appContext.getPackageName();

        try {
            this.appVersion =
                    appContext.getPackageManager().getPackageInfo(appPackageName, 0).versionName;

        } catch (PackageManager.NameNotFoundException e) {
            this.appVersion = "N/A";
        }

        SharedPreferences trustKitSharedPreferences =
//                appContext.getSharedPreferences(TrustKit.TAG, Context.MODE_PRIVATE);
                PreferenceManager.getDefaultSharedPreferences(appContext);
        String appVendorId = trustKitSharedPreferences.getString(APP_VENDOR_ID_LABEL, "");
        if (!appVendorId.equals("")) {
            this.appVendorId = appVendorId;
        } else {
            this.appVendorId = UUID.randomUUID().toString();
            SharedPreferences.Editor editor = trustKitSharedPreferences.edit();
            editor.putString(APP_VENDOR_ID_LABEL, this.appVendorId);
            editor.apply();
        }


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
     * @param includeSubdomains
     * @param enforcePinning
     * @param knownPins
     * @param validationResult
     * @throws NullPointerException
     * @throws IOException
     */
    public final void pinValidationFailed(String serverHostname, Integer serverPort,
                                          String[] certificateChain, String notedHostname,
                                          final String[] reportURIs, boolean includeSubdomains,
                                          boolean enforcePinning, String[] knownPins,
                                          PinValidationResult validationResult)
            throws NullPointerException, IOException {


        //todo try to remove this
        if (serverPort == null) {
            serverPort = 0;
        }

        if (reportURIs == null) {
            throw new NullPointerException("BackgroundReporter configuration invalid. Reporter" +
                    " was given an invalid value for reportURIs: null for domain " + notedHostname);
        }

        final PinFailureReport report = new PinFailureReport.Builder()
                .appBundleId(appPackageName)
                .appVersion(appVersion)
                .appPlatform(appPlatform)
                .appVendorId("todo")
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
        }

        new AsyncTask() {
            @Override
            protected Object doInBackground(Object[] params) {
                for (final String reportURI : reportURIs) {
                    try {
                        pinFailureReportHttpSender.send(new URL(reportURI), report);
                    } catch (MalformedURLException e) {
                        System.out.print(e.getMessage());
                        e.printStackTrace();
                    }
                }
                pinFailureReportDiskStore.save(report);
                pinFailureReportInternalSender.send(null, report);
                return null;
            }
        }.execute();

    }
}
