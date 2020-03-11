package com.datatheorem.android.trustkit.pinning;

import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.Interceptor;
import okhttp3.Request;

public class OkHttp3Helper {
    private static X509TrustManager trustManager;

    static {
        if (Build.VERSION.SDK_INT < 17) {
            trustManager = SystemTrustManager.getInstance();
        } else {
            trustManager = new OkHttpRootTrustManager();
        }
    }

    /**
     * Retrieve an {@code SSLSSocketFactory} that implements SSL pinning validation based on the
     * current TrustKit configuration. It can be used with an OkHttpClient to add SSL
     * pinning validation to the connections.
     *
     * <p>
     * The {@code SSLSocketFactory} is configured for the current TrustKit configuration and
     * will enforce the configuration's pinning policy.
     * </p>
     */
    @NonNull
    public static SSLSocketFactory getSSLSocketFactory() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new X509TrustManager[]{trustManager}, null);

            return sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
            throw new IllegalStateException("SSLSocketFactory creation failed");
        }
    }

    /**
     * Returns an {@link okhttp3.Interceptor} used to parse the hostname of the {@link Request} URL
     * and then save the hostname in the {@link OkHttpRootTrustManager} which will later be used for
     * Certificate Pinning.
     */
    @NonNull
    @RequiresApi(api = 17)
    public static Interceptor getPinningInterceptor() {
        return new OkHttp3PinningInterceptor((OkHttpRootTrustManager)trustManager);
    }

    /**
     * Returns an instance of the {@link OkHttpRootTrustManager} used for Certificate Pinning.
     */
    @NonNull
    public static X509TrustManager getTrustManager() {
        return trustManager;
    }
}
