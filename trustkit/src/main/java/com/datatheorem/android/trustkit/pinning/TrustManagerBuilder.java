package com.datatheorem.android.trustkit.pinning;

import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;

import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Set;

import javax.net.ssl.X509TrustManager;



public class TrustManagerBuilder {

    // The trust manager we will use to perform the default SSL validation
    protected static X509TrustManager baselineTrustManager = null;

    // Pinning validation can be disabled if debug-overrides is set
    protected static boolean shouldOverridePins = false;

    // The reporter that will send pinning failure reports
    protected static BackgroundReporter backgroundReporter = null;

    public static void initializeBaselineTrustManager(@Nullable Set<Certificate> debugCaCerts,
                                                      boolean debugOverridePins,
                                                      @NonNull BackgroundReporter reporter)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException,
            IOException {
        if (baselineTrustManager != null) {
            throw new IllegalStateException("TrustManagerBuilder has already been initialized");
        }
        baselineTrustManager = SystemTrustManager.getInstance();


        if (Build.VERSION.SDK_INT < 17) {
            // No pinning validation or debug overrides
            return;
        }

        shouldOverridePins = debugOverridePins;
        if ((debugCaCerts != null) && (debugCaCerts.size() > 0) && (Build.VERSION.SDK_INT < 24)) {
            // Debug overrides is enabled and we are on a pre-N device; we need to do it manually
            baselineTrustManager = DebugOverridesTrustManager.getInstance(debugCaCerts);
        }

        backgroundReporter = reporter;
    }

    public static X509TrustManager getTrustManager(@NonNull String serverHostname) {
        if (baselineTrustManager == null) {
            throw new IllegalStateException("TrustManagerBuilder has not been initialized");
        }
        if (Build.VERSION.SDK_INT < 17) {
            // No pinning validation at all for API level before 17
            // Because X509TrustManagerExtensions is not available
            return baselineTrustManager;
        }

        // Get the pinning policy for this hostname
        DomainPinningPolicy serverConfig =
                TrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname);
        if ((serverConfig == null) || (shouldOverridePins)) {
            // Domain is NOT pinned or there is a debug override - only do baseline validation
            return baselineTrustManager;
        } else {
            return new PinningTrustManager(serverHostname, baselineTrustManager);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.N)
    public static X509TrustManager getTrustManager() {
        if (baselineTrustManager == null) {
            throw new IllegalStateException("TrustManagerBuilder has not been initialized");
        }

        if (shouldOverridePins) {
            // Domain is NOT pinned or there is a debug override - only do baseline validation
            return baselineTrustManager;
        } else {
            return new PinningTrustManager(baselineTrustManager);
        }
    }

    /** Retrieve the background reporter to be used for sending pinning validation reports.
     */
    static BackgroundReporter getReporter() {
        if (backgroundReporter == null) {
            throw new IllegalStateException("TrustManagerBuilder has not been initialized");
        }
        return backgroundReporter;
    }
}
