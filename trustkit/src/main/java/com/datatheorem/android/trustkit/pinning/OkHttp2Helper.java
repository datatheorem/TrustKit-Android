package com.datatheorem.android.trustkit.pinning;

import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.squareup.okhttp.Interceptor;
import com.squareup.okhttp.Request;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

public class OkHttp2Helper {
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
     * Returns an {@link com.squareup.okhttp.Interceptor} used to parse the hostname of the
     * {@link Request} URL and then save the hostname in the {@link OkHttpRootTrustManager} which will
     * later be used for Certificate Pinning.
     */
    @NonNull
    @RequiresApi(api = 17)
    public static Interceptor getPinningInterceptor() {
        return new OkHttp2PinningInterceptor((OkHttpRootTrustManager)trustManager);
    }
}
