package com.datatheorem.android.trustkit.pinning;


public class TestableTrustManagerBuilder extends TrustKitTrustManagerBuilder {

    public static void reset() {
        baselineTrustManager = null;
    }

}
