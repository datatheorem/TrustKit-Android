package com.datatheorem.android.trustkit;


import android.content.Context;
import android.support.annotation.NonNull;

import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;

import java.util.Set;


// The main TrustKit class with some extra utility methods needed in the tests
public class TestableTrustKit extends TrustKit {
    private TestableTrustKit(Context context, TrustKitConfiguration trustKitConfiguration,
                             BackgroundReporter reporter) {
        super(context, trustKitConfiguration);
        backgroundReporter = reporter;
    }

    // This lets us inject/mock the background reporter in the tests
    public static void initWithNetworkPolicy(@NonNull Context context, BackgroundReporter reporter){
        initWithNetworkPolicy(context);
        TrustKit.getInstance().backgroundReporter = reporter;
    }

    // This lets us directly specify domain settings without parsing an XML file
    public static void init(@NonNull Context context,
                            @NonNull Set<DomainPinningPolicy> domainConfigSet,
                            BackgroundReporter reporter) {
        trustKitInstance = new TrustKit(context, new TrustKitConfiguration(domainConfigSet));
        TrustKit.getInstance().backgroundReporter = reporter;
    }

    public static void reset() {
        trustKitInstance = null;
    }
}
