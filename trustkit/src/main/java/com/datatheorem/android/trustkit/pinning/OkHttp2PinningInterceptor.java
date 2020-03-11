package com.datatheorem.android.trustkit.pinning;

import androidx.annotation.NonNull;

import com.squareup.okhttp.Interceptor;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

import java.io.IOException;

/**
 * {@link Interceptor} used to parse the hostname of the {@link Request} URL and then save the
 * hostname in the {@link OkHttpRootTrustManager} which will later be used for Certificate Pinning.
 */
public class OkHttp2PinningInterceptor implements Interceptor {
    private final OkHttpRootTrustManager mTrustManager;

    public OkHttp2PinningInterceptor(@NonNull OkHttpRootTrustManager trustManager) {
        mTrustManager = trustManager;
    }

    @Override public Response intercept(Interceptor.Chain chain) throws IOException {
        Request request = chain.request();
        String serverHostname = request.url().getHost();

        mTrustManager.setServerHostname(serverHostname);
        return chain.proceed(request);
    }
}
