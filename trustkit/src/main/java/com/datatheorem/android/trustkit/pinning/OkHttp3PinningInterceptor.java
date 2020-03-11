package com.datatheorem.android.trustkit.pinning;

import androidx.annotation.NonNull;

import java.io.IOException;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

/**
 * {@link Interceptor} used to parse the hostname of the {@link Request} URL and then save the
 * hostname in the {@link OkHttpRootTrustManager} which will later be used for Certificate Pinning.
 */
public class OkHttp3PinningInterceptor implements Interceptor {
    private final OkHttpRootTrustManager mTrustManager;

    public OkHttp3PinningInterceptor(@NonNull OkHttpRootTrustManager trustManager) {
        mTrustManager = trustManager;
    }

    @Override public Response intercept(Interceptor.Chain chain) throws IOException {
        Request request = chain.request();
        String serverHostname = request.url().host();

        mTrustManager.setServerHostname(serverHostname);
        return chain.proceed(request);
    }
}
