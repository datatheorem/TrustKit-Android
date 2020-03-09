package com.datatheorem.android.trustkit.pinning;

import androidx.annotation.NonNull;

import com.squareup.okhttp.Interceptor;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

import java.io.IOException;

/**
 * {@link Interceptor} used to parse the hostname of the {@link Request} URL and then save the
 * hostname in the {@link RootTrustManager} which will later be used for Certificate Pinning.
 */
public class PinningInterceptor2 implements Interceptor {
    private final RootTrustManager mTrustManager;

    public PinningInterceptor2(@NonNull RootTrustManager trustManager) {
        mTrustManager = trustManager;
    }

    @Override public Response intercept(Interceptor.Chain chain) throws IOException {
        Request request = chain.request();
        String serverHostname = request.url().getHost();

        mTrustManager.setServerHostname(serverHostname);
        return chain.proceed(request);
    }
}
