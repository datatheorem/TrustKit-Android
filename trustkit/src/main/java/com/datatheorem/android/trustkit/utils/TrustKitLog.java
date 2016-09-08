package com.datatheorem.android.trustkit.utils;

import android.util.Log;

import com.datatheorem.android.trustkit.BuildConfig;

public final class TrustKitLog {

    public static void e(String message) {
        if (BuildConfig.DEBUG) {
            Log.e("TrustKit", " TRUSKIT ERROR : \n" + message);
        }
    }

    public static void i(String message) {
        if (BuildConfig.DEBUG) {
            Log.i("TrustKit", " TRUSTKIT INFO : \n " + message);
        }
    }
}
