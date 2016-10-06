package com.datatheorem.android.trustkit;


import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;

import java.security.cert.Certificate;
import java.util.Set;


// The main TrustKit class with some extra utility methods needed in the tests
public class TestableTrustKit extends TrustKit {
    private TestableTrustKit(Context context, TrustKitConfiguration trustKitConfiguration,
                             BackgroundReporter reporter) {
        super(context, trustKitConfiguration);
        backgroundReporter = reporter;
    }

    // This lets us directly specify domain settings without parsing an XML file and inject/mock
    // the background reporter
    public static void init(@NonNull Set<DomainPinningPolicy> domainConfigSet,
                            @NonNull Context context,
                            BackgroundReporter reporter) {
        trustKitInstance = new TrustKit(context, new TrustKitConfiguration(domainConfigSet));
        TrustKit.getInstance().backgroundReporter = reporter;
    }


    public static void init(@NonNull Set<DomainPinningPolicy> domainConfigSet,
                            boolean shouldOverridePins,
                            @Nullable Set<Certificate> debugCaCerts,
                            @NonNull Context context,
                            BackgroundReporter reporter) {
        trustKitInstance = new TrustKit(context, new TrustKitConfiguration(domainConfigSet,
                shouldOverridePins, debugCaCerts));
        TrustKit.getInstance().backgroundReporter = reporter;
    }

    public static void reset() {
        trustKitInstance = null;
    }
}
