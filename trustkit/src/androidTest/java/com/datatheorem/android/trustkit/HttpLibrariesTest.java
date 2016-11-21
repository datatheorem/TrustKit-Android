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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

import okhttp3.OkHttpClient;
import okhttp3.Request;

import static junit.framework.Assert.assertTrue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;

@SuppressWarnings("unchecked")
@RunWith(AndroidJUnit4.class)
public class HttpLibrariesTest {

    @Mock
    private BackgroundReporter reporter;

    static private final URL testUrl;
    static {
        try {
            // The network policy for the tests has invalid pins configured for this domain
            testUrl = new URL("https://www.yahoo.com");
        } catch (MalformedURLException e) {
            throw new RuntimeException("Should never happen");
        }
    }

    @Before
    public void setUp() {
     MockitoAnnotations.initMocks(this);
        TestableTrustKit.reset();
    }

    @Test
    public void testHttpsUrlConnectionWithTrustKit() throws MalformedURLException {
        // Initialize TrustKit
        TestableTrustKit.initializeWithNetworkSecurityConfiguration(
                InstrumentationRegistry.getContext(), reporter);

        // Test a connection
        HttpsURLConnection connection = null;
        boolean didReceiveHandshakeError = false;
        try {
            connection = (HttpsURLConnection) testUrl.openConnection();
            connection.setSSLSocketFactory(new TrustKitSSLSocketFactory());

            InputStream inputStream = connection.getInputStream();
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream);

            int data = inputStreamReader.read();
            while (data != -1) {
                data = inputStreamReader.read();
            }
        } catch (IOException e) {
            if ((e.getCause() instanceof CertificateException
                    && (e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceiveHandshakeError = true;
            }
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

        assertTrue(didReceiveHandshakeError);

        // Ensure the reporter was called
        verify(reporter).pinValidationFailed(
                eq(testUrl.getHost()),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration()
                        .getPolicyForHostname(testUrl.getHost())),
                eq(PinningValidationResult.FAILED));
    }

    @Test
    public void testOkhttp3WithTrustKit() throws MalformedURLException {
        // Initialize TrustKit
        TestableTrustKit.initializeWithNetworkSecurityConfiguration(
                InstrumentationRegistry.getContext(), reporter);

        // Test a connection
        boolean didReceiveHandshakeError = false;
        OkHttpClient client = new OkHttpClient().newBuilder()
                .sslSocketFactory(new TrustKitSSLSocketFactory(),
                        TestableTrustKit.getInstance().getTrustManager(testUrl.getHost()))
                .build();
        try {
            Request request = new Request.Builder().url(testUrl).build();
            client.newCall(request).execute();
        } catch (IOException e) {
            if ((e.getCause() instanceof CertificateException
                    && (e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceiveHandshakeError = true;
            }
        }

        assertTrue(didReceiveHandshakeError);

        // Ensure the reporter was called
        verify(reporter).pinValidationFailed(
                eq(testUrl.getHost()),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration()
                        .getPolicyForHostname(testUrl.getHost())),
                eq(PinningValidationResult.FAILED));
    }
}
