package com.datatheorem.android.trustkit;

import android.content.Context;

import com.datatheorem.android.trustkit.config.PinnedDomainConfig;
import com.datatheorem.android.trustkit.config.TrustKitConfig;
import com.datatheorem.android.trustkit.report.BackgroundReporter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;

public class TrustKit {
    private static final String DEFAULT_REPORT_URI
            = "https://overmind.datatheorem.com/trustkit/report";
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

//        BackgroundReporter backgroundReporter = new BackgroundReporter(false, "test-id");
//        for (Map.Entry<String, PinnedDomainConfig> pinnedDomainConfig : trustKitConfig.entrySet()) {
//
//
////            reportUris.addAll(Arrays.asList(pinnedDomainConfig.getValue().getReportURIs()));
//            backgroundReporter.pinValidationFailed(pinnedDomainConfig.getKey(), 0, new String[]{},
//                    pinnedDomainConfig.getKey(), pinnedDomainConfig.getValue().getReportURIs(),
//                    pinnedDomainConfig.getValue().isDisableDefaultReportUri(),
//                    pinnedDomainConfig.getValue().isIncludeSubdomains(),
//                    pinnedDomainConfig.getValue().isEnforcePinning(),
//                    pinnedDomainConfig.getValue().getPublicKeyHashes(),
//                    PinValidationResult.PIN_VALIDATION_RESULT_FAILED);
//        }


    }

    public Context getAppContext() {
        return appContext;
    }

}
