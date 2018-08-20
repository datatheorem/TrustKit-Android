package com.datatheorem.android.trustkit.config;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import java.security.cert.Certificate;
import java.util.Set;

public class TestableTrustKitConfiguration extends TrustKitConfiguration {
    public TestableTrustKitConfiguration(@NonNull Set<DomainPinningPolicy> domainConfigSet) {
        super(domainConfigSet);
    }

    public TestableTrustKitConfiguration(@NonNull Set<DomainPinningPolicy> domainConfigSet,
                                    boolean shouldOverridePins,
                                    @Nullable Set<Certificate> debugCaCerts) {
        super(domainConfigSet, shouldOverridePins, debugCaCerts);
    }
}
