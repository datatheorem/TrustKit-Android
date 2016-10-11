package com.datatheorem.android.trustkit.pinning;


public class TestableTrustManagerBuilder extends TrustManagerBuilder {

    public static void reset() {
        baselineTrustManager = null;
        shouldOverridePins = false;
    }

}
