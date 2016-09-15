package com.datatheorem.android.trustkit.reporting;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.support.v4.content.LocalBroadcastManager;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.config.TrustKitConfiguration;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.net.URL;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

@Config(constants = BuildConfig.class)
@RunWith(RobolectricGradleTestRunner.class)
public class BackgroundReporterTest {


    private Context context;
    private MockBroadcastReceiver mockBroadcastReceiver;
    private MockWebServer server;
    private BackgroundReporter backgroundReporter;

//    @Mock
//    private PinnedDomainConfiguration mockPinnedConfig;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        context = RuntimeEnvironment.application.getApplicationContext();

        server = new MockWebServer();
        server.start();

        TrustKitConfiguration trustKitConfiguration = new TrustKitConfiguration();
        PinnedDomainConfiguration testPinnedDomainConfiguration = new PinnedDomainConfiguration.Builder()
                .enforcePinning(false)
                .disableDefaultReportUri(true)
                .includeSubdomains(false)
                .reportURIs(new String[]{server.url("/report").toString()})
                .build();

        trustKitConfiguration.put("www.test.com", testPinnedDomainConfiguration);
        TrustKit.init(context, trustKitConfiguration);
        //this.backgroundReporter = new BackgroundReporter(true);
        mockBroadcastReceiver = new MockBroadcastReceiver();
        LocalBroadcastManager.getInstance(context)
                .registerReceiver(mockBroadcastReceiver, new IntentFilter("test-id"));
    }

    @After
    public void tearDown() throws Exception {
        server.shutdown();
        LocalBroadcastManager.getInstance(context).unregisterReceiver(mockBroadcastReceiver);
    }


    /*
     * We test the 2 results of a pinValidationFailed call - Happy Case, no exception
     */
    @Test
    public void testPinValidationFailed_HappyCase() throws Exception {
        String certificate = "-----BEGIN CERTIFICATE-----\\nMIIE2TCCA8GgAwIBAgIQFVDTs9tHXX3ivhstj\\/NW2zANBgkqhkiG9w0BAQUFADA8\\r\\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMVGhhd3RlLCBJbmMuMRYwFAYDVQQDEw1U\\r\\naGF3dGUgU1NMIENBMB4XDTE0MTAwMjAwMDAwMFoXDTE1MTEwMTIzNTk1OVowgZcx\\r\\nCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHFAlQYWxv\\r\\nIEFsdG8xGzAZBgNVBAoUEkRhdGEgVGhlb3JlbSwgSW5jLjEkMCIGA1UECxQbU2Nh\\r\\nbiBhbmQgU2VjdXJlIE1vYmlsZSBBcHBzMRwwGgYDVQQDFBN3d3cuZGF0YXRoZW9y\\r\\nZW0uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5bCuLK3XOnNs\\r\\ni8CJvHU4H5yY3d4G1qzq7EeMydKuScMM8Nqsp4CySKTbrUhi\\/uIc08II9yBxM+q4\\r\\nNmrEg0tgVvTqvUjmMN\\/MrYQrSGVLxPq5gadI7UxfWeGSo9DpvgXaw1Vvehs2jGFK\\r\\njLzDYbzJOhv\\/pqpv4UCV\\/xfeuqmTNqqzsp+tB5Zn6gXIvIFsxfpjbeId4OWviLnC\\r\\nq957++coddvqBZd2sWkyzE2un5itXRKfnMGSBTB0cU9\\/9fXeGhzA+u01Xj+BfpHR\\r\\nuP\\/eX+rHsgc3a4hbsSWDG5278ujJ5+4To9Bn\\/rTZy7uALTM2oBZvsFX4567RhB1\\/\\r\\nIYbMDE5y8QIDAQABo4IBeTCCAXUwHgYDVR0RBBcwFYITd3d3LmRhdGF0aGVvcmVt\\r\\nLmNvbTAJBgNVHRMEAjAAMHIGA1UdIARrMGkwZwYKYIZIAYb4RQEHNjBZMCYGCCsG\\r\\nAQUFBwIBFhpodHRwczovL3d3dy50aGF3dGUuY29tL2NwczAvBggrBgEFBQcCAjAj\\r\\nDCFodHRwczovL3d3dy50aGF3dGUuY29tL3JlcG9zaXRvcnkwDgYDVR0PAQH\\/BAQD\\r\\nAgWgMB8GA1UdIwQYMBaAFKeig7s0RUA9\\/NUwTxK5PqEBn\\/bbMCsGA1UdHwQkMCIw\\r\\nIKAeoByGGmh0dHA6Ly90Yi5zeW1jYi5jb20vdGIuY3JsMB0GA1UdJQQWMBQGCCsG\\r\\nAQUFBwMBBggrBgEFBQcDAjBXBggrBgEFBQcBAQRLMEkwHwYIKwYBBQUHMAGGE2h0\\r\\ndHA6Ly90Yi5zeW1jZC5jb20wJgYIKwYBBQUHMAKGGmh0dHA6Ly90Yi5zeW1jYi5j\\r\\nb20vdGIuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQB2qnnrsAICkV9HNuBdXe+cThHV\\r\\n8+5+LBz3zGDpC1rCyq\\/DIGu0vaa\\/gasM+MswPj+AEI4f1K1x9K9KedjilVfXH+QI\\r\\ntfRzLO8iR0TbPsC6Y1avuXhal1BuvZ9UQayHRDPUEncsf+SHbIOD2GJzXy7vVk5a\\r\\nVjkvxLtjMprWIi+P7Hbn2qj03qX9KM1DnNsB28jqg7r2rpXNUPUKsxekfrMTaJgg\\r\\nzTnCN\\/EQvF5eGvAjjHckr1SlogV9o\\/y4k0x6YmPWR\\/vopMEPyOj+JhflKCdg+6w3\\r\\n79ESvZUhmgT2285c1Nu5vJjtr8x51zCNIpEoVqdkCU4c1aVZGZogSWl1rAIi\\n-----END CERTIFICATE-----";
        String pin = "pin-sha256=\"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=\"";
        server.enqueue(new MockResponse().setResponseCode(204));
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {

                return new MockResponse().setBody(request.getBody());
            }
        });
        Assert.assertEquals(false, mockBroadcastReceiver.received);

        HttpUrl baseUrl = server.url("/report");

        //backgroundReporter.pinValidationFailed("www.test.com", 443, new String[]{certificate},
        //        "www.test.com", new URL[] {baseUrl.url()}, true, false, true,
        //        new String[]{pin}, PinValidationResult.FAILED);;

        RecordedRequest request = server.takeRequest();
        //Check if the request is well formed
        Assert.assertEquals("/report", request.getPath());
        Assert.assertEquals("POST", request.getMethod());
        Assert.assertEquals(true, reportRequiredFields(request.getBody().readUtf8Line()));

        //Check if the report is sent through the system
        Assert.assertEquals(true, mockBroadcastReceiver.received);
        Assert.assertEquals(PinValidationResult.FAILED.ordinal(),
                mockBroadcastReceiver.pinValidationResult);
        Assert.assertEquals("www.test.com", mockBroadcastReceiver.notedHostname);
        Assert.assertEquals("www.test.com", mockBroadcastReceiver.serverHostname);
        Assert.assertArrayEquals(new String[]{certificate}, mockBroadcastReceiver.validatedCertificateChain);
    }

    @Test
    public void testPinValidationFailed_RateLimited() throws Exception {
        String certificate = "-----BEGIN CERTIFICATE-----\\nMIIE2TCCA8GgAwIBAgIQFVDTs9tHXX3ivhstj\\/NW2zANBgkqhkiG9w0BAQUFADA8\\r\\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMVGhhd3RlLCBJbmMuMRYwFAYDVQQDEw1U\\r\\naGF3dGUgU1NMIENBMB4XDTE0MTAwMjAwMDAwMFoXDTE1MTEwMTIzNTk1OVowgZcx\\r\\nCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHFAlQYWxv\\r\\nIEFsdG8xGzAZBgNVBAoUEkRhdGEgVGhlb3JlbSwgSW5jLjEkMCIGA1UECxQbU2Nh\\r\\nbiBhbmQgU2VjdXJlIE1vYmlsZSBBcHBzMRwwGgYDVQQDFBN3d3cuZGF0YXRoZW9y\\r\\nZW0uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5bCuLK3XOnNs\\r\\ni8CJvHU4H5yY3d4G1qzq7EeMydKuScMM8Nqsp4CySKTbrUhi\\/uIc08II9yBxM+q4\\r\\nNmrEg0tgVvTqvUjmMN\\/MrYQrSGVLxPq5gadI7UxfWeGSo9DpvgXaw1Vvehs2jGFK\\r\\njLzDYbzJOhv\\/pqpv4UCV\\/xfeuqmTNqqzsp+tB5Zn6gXIvIFsxfpjbeId4OWviLnC\\r\\nq957++coddvqBZd2sWkyzE2un5itXRKfnMGSBTB0cU9\\/9fXeGhzA+u01Xj+BfpHR\\r\\nuP\\/eX+rHsgc3a4hbsSWDG5278ujJ5+4To9Bn\\/rTZy7uALTM2oBZvsFX4567RhB1\\/\\r\\nIYbMDE5y8QIDAQABo4IBeTCCAXUwHgYDVR0RBBcwFYITd3d3LmRhdGF0aGVvcmVt\\r\\nLmNvbTAJBgNVHRMEAjAAMHIGA1UdIARrMGkwZwYKYIZIAYb4RQEHNjBZMCYGCCsG\\r\\nAQUFBwIBFhpodHRwczovL3d3dy50aGF3dGUuY29tL2NwczAvBggrBgEFBQcCAjAj\\r\\nDCFodHRwczovL3d3dy50aGF3dGUuY29tL3JlcG9zaXRvcnkwDgYDVR0PAQH\\/BAQD\\r\\nAgWgMB8GA1UdIwQYMBaAFKeig7s0RUA9\\/NUwTxK5PqEBn\\/bbMCsGA1UdHwQkMCIw\\r\\nIKAeoByGGmh0dHA6Ly90Yi5zeW1jYi5jb20vdGIuY3JsMB0GA1UdJQQWMBQGCCsG\\r\\nAQUFBwMBBggrBgEFBQcDAjBXBggrBgEFBQcBAQRLMEkwHwYIKwYBBQUHMAGGE2h0\\r\\ndHA6Ly90Yi5zeW1jZC5jb20wJgYIKwYBBQUHMAKGGmh0dHA6Ly90Yi5zeW1jYi5j\\r\\nb20vdGIuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQB2qnnrsAICkV9HNuBdXe+cThHV\\r\\n8+5+LBz3zGDpC1rCyq\\/DIGu0vaa\\/gasM+MswPj+AEI4f1K1x9K9KedjilVfXH+QI\\r\\ntfRzLO8iR0TbPsC6Y1avuXhal1BuvZ9UQayHRDPUEncsf+SHbIOD2GJzXy7vVk5a\\r\\nVjkvxLtjMprWIi+P7Hbn2qj03qX9KM1DnNsB28jqg7r2rpXNUPUKsxekfrMTaJgg\\r\\nzTnCN\\/EQvF5eGvAjjHckr1SlogV9o\\/y4k0x6YmPWR\\/vopMEPyOj+JhflKCdg+6w3\\r\\n79ESvZUhmgT2285c1Nu5vJjtr8x51zCNIpEoVqdkCU4c1aVZGZogSWl1rAIi\\n-----END CERTIFICATE-----";
        String pin = "pin-sha256=\"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=\"";
        server.enqueue(new MockResponse().setResponseCode(204));
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {

                return new MockResponse().setBody(request.getBody());
            }
        });
        Assert.assertEquals(false, mockBroadcastReceiver.received);

        HttpUrl baseUrl = server.url("/report");

        //backgroundReporter.pinValidationFailed("www.test.com", 442, new String[]{certificate},
        //        "www.test.com", new URL[] {baseUrl.url()}, true, false, true,
        //        new String[]{pin}, PinValidationResult.FAILED);;


        //Check if the report is not sent through the system because the same report was sent
        //less than 24h ago
        Assert.assertEquals(false, mockBroadcastReceiver.received);

    }

    private boolean reportRequiredFields(String json) {
        return json.contains("app-bundle-id")  && json.contains("app-version")
                && json.contains("app-vendor-id") && json.contains("app-platform")
                && json.contains("trustkit-version") && json.contains("hostname")
                && json.contains("port") && json.contains("noted-hostname")
                && json.contains("include-subdomains") && json.contains("enforce-pinning")
                && json.contains("validated-certificate-chain") && json.contains("date-time")
                && json.contains("known-pins") && json.contains("validation-result");
    }


    private class MockBroadcastReceiver extends BroadcastReceiver {
        public boolean received = false;
        public String serverHostname;
        public String notedHostname;
        public String[] validatedCertificateChain;
        public int pinValidationResult;
        @Override
        public void onReceive(Context context, Intent intent) {
            received = true;
            serverHostname = intent.getStringExtra(PinFailureReportInternalSender.TRUSTKIT_INTENT_SERVER_HOSTNAME_KEY);
            notedHostname = intent.getStringExtra(PinFailureReportInternalSender.TRUSTKIT_INTENT_NOTED_HOSTNAME_KEY);
            validatedCertificateChain = intent.getStringArrayExtra(PinFailureReportInternalSender.TRUSTKIT_INTENT_CERTIFICATE_CHAIN_KEY);
            pinValidationResult = intent.getIntExtra(PinFailureReportInternalSender.TRUSTKIT_INTENT_VALIDATION_RESULT_KEY, -1);
        }
    }
}


