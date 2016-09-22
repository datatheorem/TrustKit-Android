package com.datatheorem.android.trustkit.pinning;

import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.net.ssl.X509TrustManager;


public class TrustManagerBuilder {

    // The trust manager we will use to perform the default SSL validation
    protected static X509TrustManager baselineTrustManager = null;

    public static void initializeBaselineTrustManager(@Nullable Certificate debugCaFile)
            throws CertificateException, NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException, IOException {

        if (baselineTrustManager != null) {
            throw new IllegalStateException("TrustKit has already been initialized");
        }

        baselineTrustManager = SystemTrustManager.getDefault();
        if ((debugCaFile != null) && (Build.VERSION.SDK_INT < 24)) {
            // Debug overrides is enabled and we are on a pre-N device; we need to do it manually
            baselineTrustManager = new DebugOverridesTrustManager(debugCaFile);
        }
    }

    public static X509TrustManager getTrustManager(@NonNull String serverHostname) {
        if (baselineTrustManager == null) {
            throw new IllegalStateException("TrustKit has not been initialized");
        }
        PinnedDomainConfiguration serverConfig =
                TrustKit.getInstance().getConfiguration().findConfiguration(serverHostname);

        if (serverConfig == null) {
            // Domain is NOT pinned - only do baseline validation
            return baselineTrustManager;
        } else {
            return new PinningTrustManager(serverHostname, serverConfig, baselineTrustManager);
        }
    }
}
