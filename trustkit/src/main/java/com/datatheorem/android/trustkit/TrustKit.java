package com.datatheorem.android.trustkit;

import android.content.Context;

import com.datatheorem.android.trustkit.config.PinnedDomainConfig;
import com.datatheorem.android.trustkit.config.TrustKitConfig;
import com.datatheorem.android.trustkit.report.BackgroundReporter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;

public class TrustKit {

    private Context appContext;
    private TrustKitConfig trustKitConfig;
    private static TrustKit trustKitInstance;

    private TrustKit(Context context, TrustKitConfig trustKitConfig) {
        this.appContext = context;
        this.trustKitConfig = trustKitConfig;
    }

    public static TrustKit getInstance() {
        return trustKitInstance;
    }


    public static void init(Context appContext, TrustKitConfig trustKitConfig) {
        if (trustKitInstance == null) {
            trustKitInstance = new TrustKit(appContext, trustKitConfig);
        }



    }

    public Context getAppContext() {
        return appContext;
    }

}
