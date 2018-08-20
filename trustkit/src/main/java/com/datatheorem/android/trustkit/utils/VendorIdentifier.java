package com.datatheorem.android.trustkit.utils;


import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.support.annotation.NonNull;
import java.util.UUID;

/**
 * When TrustKit sends a report, it also sends a randomly-generated identifier to uniquely identify
 * a specific App install (ie. an instance of the App running on a specific device). It is the least
 * intrusive way to detect reports coming from the same device.
 */
public class VendorIdentifier {

    private static final String TRUSTKIT_VENDOR_ID = "TRUSTKIT_VENDOR_ID";

    @NonNull
    public static String getOrCreate(@NonNull Context appContext) {
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
}
