package com.datatheorem.android.trustkit;


import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.config.TestableTrustKitConfiguration;
import com.datatheorem.android.trustkit.config.TrustKitConfiguration;
import com.datatheorem.android.trustkit.pinning.TestableTrustManagerBuilder;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;

import java.security.cert.Certificate;
import java.util.Set;


// The main TrustKit class with some extra utility methods needed in the tests
public class TestableTrustKit extends TrustKit {
    private TestableTrustKit(Context context, TrustKitConfiguration trustKitConfiguration,
                             BackgroundReporter reporter) {
        super(context, trustKitConfiguration);
        TestableTrustManagerBuilder.setReporter(reporter);
    }


    public static TrustKit initializeWithNetworkSecurityConfiguration(@NonNull Context context,
                                                                      BackgroundReporter reporter) {
        TrustKit.initializeWithNetworkSecurityConfiguration(context);
        TestableTrustManagerBuilder.setReporter(reporter);
        return TrustKit.getInstance();
    }

    // This lets us directly specify domain settings without parsing an XML file and inject/mock
    // the background reporter
    public static void init(@NonNull Set<DomainPinningPolicy> domainConfigSet,
                            @NonNull Context context,
                            BackgroundReporter reporter) {
        trustKitInstance = new TrustKit(context, new TestableTrustKitConfiguration(domainConfigSet));
        TestableTrustManagerBuilder.setReporter(reporter);
    }


    public static void init(@NonNull Set<DomainPinningPolicy> domainConfigSet,
                            boolean shouldOverridePins,
                            @Nullable Set<Certificate> debugCaCerts,
                            @NonNull Context context,
                            BackgroundReporter reporter) {
        trustKitInstance = new TrustKit(context, new TestableTrustKitConfiguration(domainConfigSet,
                shouldOverridePins, debugCaCerts));
        TestableTrustManagerBuilder.setReporter(reporter);
    }

    public static void reset() {
        trustKitInstance = null;
        TestableTrustManagerBuilder.reset();
    }
}
