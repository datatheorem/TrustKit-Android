package com.datatheorem.android.trustkit;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.content.res.XmlResourceParser;
import android.os.Build;
import android.preference.PreferenceManager;
import android.security.NetworkSecurityPolicy;

import com.datatheorem.android.trustkit.config.ConfigurationException;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.util.UUID;


public class TrustKit {

    private static final String TRUSTKIT_VENDOR_ID = "TRUSTKIT_VENDOR_ID";
    private final TrustKitConfiguration trustKitConfiguration;
    private final BackgroundReporter backgroundReporter;
    private static TrustKit trustKitInstance;

    private TrustKit(Context context, TrustKitConfiguration trustKitConfiguration) {
        if (trustKitConfiguration != null) {
            this.trustKitConfiguration = trustKitConfiguration;
        } else {
            throw new NullPointerException("No trustkitConfiguration provided.");
        }

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
        if(getNetworkSecurityPolicy(context) != null
                && Build.VERSION.SDK_INT > Build.VERSION_CODES.N) {
            init(context, TrustKitConfiguration.fromXmlPolicy(getNetworkSecurityPolicy(context)));
        } else {
            init(context, TrustKitConfiguration.fromXmlPolicy(getTrustKitPolicy(context)));
        }
    }


    public static void init(Context appContext, TrustKitConfiguration trustKitConfiguration) {

        if (getNetworkSecurityPolicy(appContext) != null
                && Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {

            throw new ConfigurationException("A NetworkSecurityConfigurationPolicy is already " +
                    "defined. Please use TrustKit.initWithNetworkPolicy(Context context); instead");
        }

        if (trustKitInstance == null) {
            trustKitInstance = new TrustKit(appContext, trustKitConfiguration);
        } else {
            throw new IllegalStateException("Already instantiated");
        }


        //PinningTrustManager manager = new PinningTrustManager();
    }

    public TrustKitConfiguration getConfiguration() { return trustKitConfiguration; }
    public BackgroundReporter getReporter() { return backgroundReporter; }

    private static XmlResourceParser getTrustKitPolicy(Context context) {
        try {
            ApplicationInfo ai =
                    context.getPackageManager().getApplicationInfo(context.getPackageName(),
                            PackageManager.GET_META_DATA);
            return context.getResources().getXml(ai.metaData.getInt("trustkit_configuration"));
        } catch (PackageManager.NameNotFoundException e) {
            throw new IllegalStateException("Should never happen");
        } catch (Resources.NotFoundException ex) {
            return null;
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private static XmlResourceParser getNetworkSecurityPolicy(Context context) {

        if (NetworkSecurityPolicy.getInstance() != null) {
            try {
                final int networkSecurityConfigId = context.getResources().getIdentifier(
                        "network_security_config", "xml", context.getPackageName());

                return context.getResources().getXml(networkSecurityConfigId);
            } catch (Resources.NotFoundException e) {
                return null;
            }
        }
        return null;
    }
}
