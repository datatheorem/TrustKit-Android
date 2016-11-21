package com.datatheorem.android.trustkit.utils;

import android.util.Log;

import com.datatheorem.android.trustkit.BuildConfig;


public final class TrustKitLog {

    public static void i(String message) {
        // Disable debug printing for Release build
        if (BuildConfig.DEBUG) {
            Log.i("TrustKit", message);
        }
    }

    public static void w(String message) {
        Log.i("TrustKit", message);
    }
}
