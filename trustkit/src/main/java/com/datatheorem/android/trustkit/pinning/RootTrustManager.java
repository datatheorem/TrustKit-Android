package com.datatheorem.android.trustkit.pinning;

import android.net.http.X509TrustManagerExtensions;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.config.DomainPinningPolicy;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * {@link X509TrustManager} used for Certificate Pinning.
 *
 * <p>This trust manager delegates to the appropriate {@link PinningTrustManager} decided by the
 * hostname set by the {@link PinningInterceptor}.</p>
 */
@RequiresApi(api = 17)
class RootTrustManager implements X509TrustManager {
    private final ThreadLocal<String> mServerHostname = new ThreadLocal<>();

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        TrustKit.getInstance().getTrustManager(mServerHostname.get()).checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        String host = mServerHostname.get();
        DomainPinningPolicy serverConfig =
                TrustKit.getInstance().getConfiguration().getPolicyForHostname(host);
        //This check is needed for compatibility with the Platform default's implementation of
        //the Trust Manager. For APIs 24 and greater, the Platform's default TrustManager states
        //that it requires usage of the hostname-aware version of checkServerTrusted for app's that
        //implement Android's network_security_config file.
        if (serverConfig == null) {
            new X509TrustManagerExtensions(TrustKit.getInstance().getTrustManager(host)).checkServerTrusted(chain, authType, host);
        } else {
            TrustKit.getInstance().getTrustManager(host).checkServerTrusted(chain, authType);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    void setServerHostname(@NonNull String serverHostname) {
        mServerHostname.set(serverHostname);
    }
}
