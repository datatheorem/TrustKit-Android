package com.datatheorem.android.trustkit;

import android.content.Context;

import com.datatheorem.android.trustkit.config.PinnedDomainConfig;

import java.util.Map;

public class TrustKit {
    private Context appContext;
    private Map<String, PinnedDomainConfig> pinnedDomainConfigs;
    private static TrustKit trustKitInstance;

    private TrustKit(Context context, Map<String, PinnedDomainConfig> pinnedDomainConfigs) {
        this.appContext = context;
        this.pinnedDomainConfigs = pinnedDomainConfigs;
    }

    public static TrustKit getInstance() {
        return trustKitInstance;
    }


    public static void init(Context appContext, Map<String, PinnedDomainConfig> pinnedDomainConfigs) {
        if (trustKitInstance == null) {
            trustKitInstance = new TrustKit(appContext, pinnedDomainConfigs);
        }
    }

    public Context getAppContext() {
        return appContext;
    }

}
