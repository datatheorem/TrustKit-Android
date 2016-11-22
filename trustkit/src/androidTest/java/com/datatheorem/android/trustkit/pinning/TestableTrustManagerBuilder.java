package com.datatheorem.android.trustkit.pinning;


import com.datatheorem.android.trustkit.reporting.BackgroundReporter;

public class TestableTrustManagerBuilder extends TrustManagerBuilder {

    public static void setReporter(BackgroundReporter reporter) {
        backgroundReporter = reporter;
    }

    public static void reset() {
        baselineTrustManager = null;
        shouldOverridePins = false;
    }
}
