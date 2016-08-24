package com.datatheorem.android.trustkit.report;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.preference.PreferenceManager;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.report.data.PinFailureReport;
import com.datatheorem.android.trustkit.report.data.PinFailureReportDiskStore;
import com.datatheorem.android.trustkit.report.data.PinFailureReportStore;
import com.datatheorem.android.trustkit.report.internals.PinFailureReportHttpSender;
import com.datatheorem.android.trustkit.report.internals.PinFailureReportInternalSender;
import com.datatheorem.android.trustkit.report.internals.ReportsRateLimiter;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.io.IOException;
import java.net.URL;
import java.sql.Date;
import java.util.UUID;


/**
 * The BackgroundReporter save a report when a pinning validation fail and send the report
 * to the specific URI.
 */
public final class BackgroundReporter {
    private final String APP_VENDOR_ID_LABEL = "APP_VENDOR_ID";

    // Main application environment information
    private String appPackageName;
    private String appVersion;
    private String appVendorId;
    private String appPlatform;

    // Configuration and Objects managing all the operation done by the BackgroundReporter
    private boolean shouldRateLimitsReports;
    private PinFailureReportStore tskPinFailureReportDiskCache;
    private PinFailureReportHttpSender pinFailureReportHttpSender;
    private PinFailureReportInternalSender pinFailureReportInternalSender;



    public BackgroundReporter(boolean shouldRateLimitsReports,
                              PinFailureReportStore pinFailureReportStore,
                              PinFailureReportHttpSender pinFailureReportHttpSender,
                              PinFailureReportInternalSender pinFailureReportInternalSender) {
        this.shouldRateLimitsReports = shouldRateLimitsReports;
        this.tskPinFailureReportDiskCache = pinFailureReportStore;
        this.pinFailureReportHttpSender = pinFailureReportHttpSender;
        this.pinFailureReportInternalSender = pinFailureReportInternalSender;
        Context appContext = TrustKit.getInstance().getAppContext();

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
                                                String[] reportURIs, boolean includeSubdomains,
                                                boolean enforcePinning, String[] knownPins,
                                                PinValidationResult validationResult)
            throws NullPointerException, IOException {

        //todo try to remove this
        if (serverPort == null) {
            serverPort = 0;
        }

        if (reportURIs == null) {
            throw new NullPointerException("TSKBackgroudReporter configuration invalid. Reporter" +
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

        tskPinFailureReportDiskCache.save(report);

//        TSKPinFailureReportCloudStore cloudStore = new TSKPinFailureReportCloudStore();
        for (String reportURI : reportURIs) {
            // #1 Using a Sender object two interfaces
            pinFailureReportHttpSender.send(new URL(reportURI), report);

            // #2 Using a "Cloud" store object and using the same interface as DiskStore
        }

        pinFailureReportInternalSender.send(null, report);
    }
}
