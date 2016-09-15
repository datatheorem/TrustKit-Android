package com.datatheorem.android.trustkit;


import android.content.Context;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;


// The main TrustKit class with some extra utility methods needed in the tests
public class DebugTrustKit extends TrustKit {
    private DebugTrustKit(Context context, TrustKitConfiguration trustKitConfiguration,
                          BackgroundReporter reporter) {
        super(context, trustKitConfiguration);
        backgroundReporter = reporter;
    }

    public static void init(Context appContext, TrustKitConfiguration trustKitConfiguration,
                            BackgroundReporter reporter) {
        if (trustKitInstance == null) {
            trustKitInstance = new DebugTrustKit(appContext, trustKitConfiguration, reporter);
        }
        else {
            throw new IllegalStateException("TrustKit was already initialized");
        }
    }

    public static void resetConfiguration() {
        trustKitInstance = null;
    }
}
