package com.datatheorem.android.trustkit;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.XmlResourceParser;
import android.preference.PreferenceManager;

import com.datatheorem.android.trustkit.config.TrustKitConfiguration;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.util.UUID;


public class TrustKit {

    private static final String TRUSTKIT_VENDOR_ID = "TRUSTKIT_VENDOR_ID";
    private final TrustKitConfiguration trustKitConfiguration;
    protected BackgroundReporter backgroundReporter;
    protected static TrustKit trustKitInstance;


    protected TrustKit(Context context, TrustKitConfiguration trustKitConfiguration) {
        this.trustKitConfiguration = trustKitConfiguration;

        // Create the background reporter for sending pin failure reports
        String appPackageName = context.getPackageName();
        String appVersion;
        try {
            appVersion = context.getPackageManager().getPackageInfo(appPackageName, 0).versionName;

        } catch (PackageManager.NameNotFoundException e) {
            appVersion = "N/A";
        }
        String appVendorId = getOrCreateVendorIdentifier(context);
        this.backgroundReporter = new BackgroundReporter(true, appPackageName, appVersion,
                appVendorId);
    }

    private static String getOrCreateVendorIdentifier(Context appContext) {
        SharedPreferences trustKitSharedPreferences =
                PreferenceManager.getDefaultSharedPreferences(appContext);
        // We store the vendor ID in the App's preferences
        String appVendorId = trustKitSharedPreferences.getString(TRUSTKIT_VENDOR_ID, "");
        if (appVendorId.equals("")) {
            // First time the App is running: generate and store a new vendor ID
            TrustKitLog.i("Generating new vendor identifier...");
            appVendorId = UUID.randomUUID().toString();
            SharedPreferences.Editor editor = trustKitSharedPreferences.edit();
            editor.putString(TRUSTKIT_VENDOR_ID, appVendorId);
            editor.apply();
        }
        return appVendorId;
    }

    public static TrustKit getInstance() {
        return trustKitInstance;
    }

    public static void initWithNetworkPolicy(Context context) {
        final int networkSecurityConfigId = context.getResources().getIdentifier(
                "network_security_config", "xml", context.getPackageName()
        );

        XmlResourceParser parser = context.getResources().getXml(networkSecurityConfigId);
        init(context, TrustKitConfiguration.fromXmlPolicy(parser));
    }

    public static void init(Context appContext, TrustKitConfiguration trustKitConfiguration) {
        if (trustKitInstance == null) {
            trustKitInstance = new TrustKit(appContext, trustKitConfiguration);
        }
        else {
            throw new IllegalStateException("TrustKit was already initialized");
        }
    }

    public TrustKitConfiguration getConfiguration() { return trustKitConfiguration; }
    public BackgroundReporter getReporter() { return backgroundReporter; }

}
