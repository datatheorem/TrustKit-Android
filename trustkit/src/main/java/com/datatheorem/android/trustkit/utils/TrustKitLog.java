package com.datatheorem.android.trustkit.utils;

import android.util.Log;

import com.datatheorem.android.trustkit.BuildConfig;

// TODO(ad): Clean this up
public final class TrustKitLog {
    private static final String INFO_LABEL = " TRUSTKIT INFO : \n ";
    private static final String ERROR_LABEL = " TRUSTKIT ERROR : \n";
    private static final String WARNING_LABEL = " TRUSTKIT WARNING : \n";

    public static void e(String message) {
        if (BuildConfig.DEBUG) {
            Log.e("TrustKit", ERROR_LABEL + message);
        }
    }

    public static void i(String message) {
        if (BuildConfig.DEBUG) {
            Log.i("TrustKit", INFO_LABEL + message);
        }
    }

    public static void w(String message) {
        Log.i("TrustKit", WARNING_LABEL + message);
    }
}
