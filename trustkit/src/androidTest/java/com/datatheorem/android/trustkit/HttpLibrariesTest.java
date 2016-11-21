package com.datatheorem.android.trustkit;

import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.pinning.PinningValidationResult;
import com.datatheorem.android.trustkit.pinning.TrustKitSSLSocketFactory;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import okhttp3.OkHttpClient;
import okhttp3.Request;

import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;

@SuppressWarnings("unchecked")
@RunWith(AndroidJUnit4.class)
public class HttpLibrariesTest {

    @Mock
    private BackgroundReporter reporter;

    private String serverHostname = "expired.badssl.com";

    @Before
    public void setUp() {
     MockitoAnnotations.initMocks(this);
        TestableTrustKit.reset();
    }

    @Test
    public void httpsUrlConnectionWithTrustKit() throws MalformedURLException{
        final DomainPinningPolicy domainPinningPolicy = new DomainPinningPolicy.Builder()
                .setHostname(serverHostname)
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();
        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPinningPolicy); }},
                InstrumentationRegistry.getContext(), reporter);
        HttpsURLConnection httpsURLConnection = null;
        URL url = new URL("https://"+serverHostname);
        try {
            httpsURLConnection = (HttpsURLConnection) url.openConnection();
            httpsURLConnection.setSSLSocketFactory(new TrustKitSSLSocketFactory());

            InputStream inputStream = httpsURLConnection.getInputStream();
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream);

            int data = inputStreamReader.read();
            while (data != -1) {
                char c = (char) data;
                data = inputStreamReader.read();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            httpsURLConnection.disconnect();
            verify(reporter).pinValidationFailed(
                    eq(serverHostname),
                    eq(0),
                    (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                    (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                    eq(TestableTrustKit.getInstance().getConfiguration()
                            .getPolicyForHostname(serverHostname)),
                    eq(PinningValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED));
        }

    }

    @Test
    public void okhttp3WithTrustKit() throws MalformedURLException {
        final DomainPinningPolicy domainPinningPolicy = new DomainPinningPolicy.Builder()
                .setHostname(serverHostname)
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();
        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPinningPolicy); }},
                InstrumentationRegistry.getContext(), reporter);
        OkHttpClient client = new OkHttpClient().newBuilder()
                .sslSocketFactory(new TrustKitSSLSocketFactory(),
                        TestableTrustKit.getInstance().getTrustManager("https://"+serverHostname))
                .build();

        try {
            Request request = new Request.Builder().url(new URL("https://" + serverHostname))
                    .build();
            client.newCall(request).execute();
        } catch (IOException e) {

            verify(reporter).pinValidationFailed(
                    eq(serverHostname),
                    eq(0),
                    (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                    (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                    eq(TestableTrustKit.getInstance().getConfiguration()
                            .getPolicyForHostname(serverHostname)),
                    eq(PinningValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED));
        }

    }
}
