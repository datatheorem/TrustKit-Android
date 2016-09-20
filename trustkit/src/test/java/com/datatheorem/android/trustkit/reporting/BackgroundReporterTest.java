package com.datatheorem.android.trustkit.reporting;

import android.content.Context;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.TrustKitConfiguration;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

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
    private MockWebServer server;
    private BackgroundReporter backgroundReporter;
    private X509Certificate mockCertificate;


    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        context = RuntimeEnvironment.application.getApplicationContext();

        String pin = "pin-sha256=\"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=\"";
        String pin2 = "pin-sha256=\"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8=\"";
        Set<String> pins = new HashSet<>();
        pins.add(pin);
        pins.add(pin2);

        server = new MockWebServer();
        server.start();

        TrustKitConfiguration trustKitConfiguration = new TrustKitConfiguration();
        PinnedDomainConfiguration testPinnedDomainConfiguration = new PinnedDomainConfiguration.Builder()
                .shouldEnforcePinning(false)
                .shouldDisableDefaultReportUri(true)
                .shouldIncludeSubdomains(false)
                .reportUris(new String[]{server.url("/report").toString()})
                .publicKeyHashes(pins)
                .pinnedDomainName("www.test.com")
                .build();

        trustKitConfiguration.add(testPinnedDomainConfiguration);
        //TrustKit.init(context, trustKitConfiguration);
        this.backgroundReporter =
                new BackgroundReporter(true, RuntimeEnvironment.application.getPackageName(),
                        RuntimeEnvironment.application.getPackageManager().getPackageInfo(
                                RuntimeEnvironment.application.getPackageName(), 0).versionName,
                        UUID.randomUUID().toString());

    }

    @After
    public void tearDown() throws Exception {
        server.shutdown();

    }


    /*
     * We test the 2 results of a pinValidationFailed call - Happy Case, no exception
     */
    @Test
    public void testPinValidationFailed_HappyCase() throws Exception {
        String pin = "pin-sha256=\"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=\"";
        String pin2 = "pin-sha256=\"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8=\"";
        server.enqueue(new MockResponse().setResponseCode(204));
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                return new MockResponse().setBody(request.getBody());
            }
        });

        HttpUrl baseUrl = server.url("/report");
        Set<String> pins = new HashSet<>();
        pins.add(pin);
        pins.add(pin2);

        PinnedDomainConfiguration mockPinnedDomainConfiguration =
                new PinnedDomainConfiguration.Builder()
                .pinnedDomainName("www.test.com")
                .shouldIncludeSubdomains(true)
                .shouldEnforcePinning(true)
                .reportUris(new String[]{String.valueOf(baseUrl)})
                .publicKeyHashes(pins).build();

        ArrayList<X509Certificate> certChain =
                (ArrayList<X509Certificate>) Arrays.asList(getMockCertificate());
        backgroundReporter.pinValidationFailed("www.test.com", 443, certChain, certChain,
                mockPinnedDomainConfiguration, PinValidationResult.FAILED);

        RecordedRequest request = server.takeRequest();
        //Check if the request is well formed
        Assert.assertEquals("/report", request.getPath());
        Assert.assertEquals("POST", request.getMethod());
        Assert.assertEquals(true, reportRequiredFields(request.getBody().readUtf8Line()));
    }

//    @Test
//    public void testPinValidationFailed_RateLimited() throws Exception {
//        String certificate = "-----BEGIN CERTIFICATE-----\\nMIIE2TCCA8GgAwIBAgIQFVDTs9tHXX3ivhstj\\/NW2zANBgkqhkiG9w0BAQUFADA8\\r\\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMVGhhd3RlLCBJbmMuMRYwFAYDVQQDEw1U\\r\\naGF3dGUgU1NMIENBMB4XDTE0MTAwMjAwMDAwMFoXDTE1MTEwMTIzNTk1OVowgZcx\\r\\nCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHFAlQYWxv\\r\\nIEFsdG8xGzAZBgNVBAoUEkRhdGEgVGhlb3JlbSwgSW5jLjEkMCIGA1UECxQbU2Nh\\r\\nbiBhbmQgU2VjdXJlIE1vYmlsZSBBcHBzMRwwGgYDVQQDFBN3d3cuZGF0YXRoZW9y\\r\\nZW0uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5bCuLK3XOnNs\\r\\ni8CJvHU4H5yY3d4G1qzq7EeMydKuScMM8Nqsp4CySKTbrUhi\\/uIc08II9yBxM+q4\\r\\nNmrEg0tgVvTqvUjmMN\\/MrYQrSGVLxPq5gadI7UxfWeGSo9DpvgXaw1Vvehs2jGFK\\r\\njLzDYbzJOhv\\/pqpv4UCV\\/xfeuqmTNqqzsp+tB5Zn6gXIvIFsxfpjbeId4OWviLnC\\r\\nq957++coddvqBZd2sWkyzE2un5itXRKfnMGSBTB0cU9\\/9fXeGhzA+u01Xj+BfpHR\\r\\nuP\\/eX+rHsgc3a4hbsSWDG5278ujJ5+4To9Bn\\/rTZy7uALTM2oBZvsFX4567RhB1\\/\\r\\nIYbMDE5y8QIDAQABo4IBeTCCAXUwHgYDVR0RBBcwFYITd3d3LmRhdGF0aGVvcmVt\\r\\nLmNvbTAJBgNVHRMEAjAAMHIGA1UdIARrMGkwZwYKYIZIAYb4RQEHNjBZMCYGCCsG\\r\\nAQUFBwIBFhpodHRwczovL3d3dy50aGF3dGUuY29tL2NwczAvBggrBgEFBQcCAjAj\\r\\nDCFodHRwczovL3d3dy50aGF3dGUuY29tL3JlcG9zaXRvcnkwDgYDVR0PAQH\\/BAQD\\r\\nAgWgMB8GA1UdIwQYMBaAFKeig7s0RUA9\\/NUwTxK5PqEBn\\/bbMCsGA1UdHwQkMCIw\\r\\nIKAeoByGGmh0dHA6Ly90Yi5zeW1jYi5jb20vdGIuY3JsMB0GA1UdJQQWMBQGCCsG\\r\\nAQUFBwMBBggrBgEFBQcDAjBXBggrBgEFBQcBAQRLMEkwHwYIKwYBBQUHMAGGE2h0\\r\\ndHA6Ly90Yi5zeW1jZC5jb20wJgYIKwYBBQUHMAKGGmh0dHA6Ly90Yi5zeW1jYi5j\\r\\nb20vdGIuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQB2qnnrsAICkV9HNuBdXe+cThHV\\r\\n8+5+LBz3zGDpC1rCyq\\/DIGu0vaa\\/gasM+MswPj+AEI4f1K1x9K9KedjilVfXH+QI\\r\\ntfRzLO8iR0TbPsC6Y1avuXhal1BuvZ9UQayHRDPUEncsf+SHbIOD2GJzXy7vVk5a\\r\\nVjkvxLtjMprWIi+P7Hbn2qj03qX9KM1DnNsB28jqg7r2rpXNUPUKsxekfrMTaJgg\\r\\nzTnCN\\/EQvF5eGvAjjHckr1SlogV9o\\/y4k0x6YmPWR\\/vopMEPyOj+JhflKCdg+6w3\\r\\n79ESvZUhmgT2285c1Nu5vJjtr8x51zCNIpEoVqdkCU4c1aVZGZogSWl1rAIi\\n-----END CERTIFICATE-----";
//        String pin = "pin-sha256=\"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=\"";
//        server.enqueue(new MockResponse().setResponseCode(204));
//        server.setDispatcher(new Dispatcher() {
//            @Override
//            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
//
//                return new MockResponse().setBody(request.getBody());
//            }
//        });
//        Assert.assertEquals(false, mockBroadcastReceiver.received);
//
//        HttpUrl baseUrl = server.url("/report");
//
//        backgroundReporter.pinValidationFailed("www.test.com", 442, new String[]{certificate},
//                "www.test.com", new URL[] {baseUrl.url()}, true, false, true,
//                new String[]{pin}, PinValidationResult.FAILED);;
//
//
//        //Check if the report is not sent through the system because the same report was sent
//        //less than 24h ago
//        Assert.assertEquals(false, mockBroadcastReceiver.received);
//
//    }

    private boolean reportRequiredFields(String json) {
        return json.contains("app-bundle-id")  && json.contains("app-version")
                && json.contains("app-vendor-id") && json.contains("app-platform")
                && json.contains("trustkit-version") && json.contains("hostname")
                && json.contains("port") && json.contains("noted-hostname")
                && json.contains("include-subdomains") && json.contains("enforce-pinning")
                && json.contains("validated-certificate-chain") && json.contains("date-time")
                && json.contains("known-pins") && json.contains("validation-result");
    }

    private X509Certificate getMockCertificate() {
//        String certificate = "-----BEGIN CERTIFICATE-----\n" +
//                "MIIE2TCCA8GgAwIBAgIQFVDTs9tHXX3ivhstjNW2zANBgkqhkiG9w0BAQUFADA8\n" +
//                "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMVGhhd3RlLCBJbmMuMRYwFAYDVQQDEw1U\n" +
//                "aGF3dGUgU1NMIENBMB4XDTE0MTAwMjAwMDAwMFoXDTE1MTEwMTIzNTk1OVowgZcx\n" +
//                "CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHFAlQYWxv\n" +
//                "IEFsdG8xGzAZBgNVBAoUEkRhdGEgVGhlb3JlbSwgSW5jLjEkMCIGA1UECxQbU2Nh\n" +
//                "biBhbmQgU2VjdXJlIE1vYmlsZSBBcHBzMRwwGgYDVQQDFBN3d3cuZGF0YXRoZW9y\n" +
//                "ZW0uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5bCuLK3XOnNs\n" +
//                "i8CJvHU4H5yY3d4G1qzq7EeMydKuScMM8Nqsp4CySKTbrUhi/uIc08II9yBxM+q4\n" +
//                "NmrEg0tgVvTqvUjmMN/MrYQrSGVLxPq5gadI7UxfWeGSo9DpvgXaw1Vvehs2jGFK\n" +
//                "jLzDYbzJOhv/pqpv4UCV/xfeuqmTNqqzsp+tB5Zn6gXIvIFsxfpjbeId4OWviLnC\n" +
//                "q957++coddvqBZd2sWkyzE2un5itXRKfnMGSBTB0cU9/9fXeGhzA+u01Xj+BfpHR\n" +
//                "uP/eX+rHsgc3a4hbsSWDG5278ujJ5+4To9Bn/rTZy7uALTM2oBZvsFX4567RhB1\n" +
//                "IYbMDE5y8QIDAQABo4IBeTCCAXUwHgYDVR0RBBcwFYITd3d3LmRhdGF0aGVvcmVt\n" +
//                "LmNvbTAJBgNVHRMEAjAAMHIGA1UdIARrMGkwZwYKYIZIAYb4RQEHNjBZMCYGCCsG\n" +
//                "AQUFBwIBFhpodHRwczovL3d3dy50aGF3dGUuY29tL2NwczAvBggrBgEFBQcCAjAj\n" +
//                "DCFodHRwczovL3d3dy50aGF3dGUuY29tL3JlcG9zaXRvcnkwDgYDVR0PAQH/BAQD\n" +
//                "AgWgMB8GA1UdIwQYMBaAFKeig7s0RUA9/NUwTxK5PqEBn/bbMCsGA1UdHwQkMCIw\n" +
//                "IKAeoByGGmh0dHA6Ly90Yi5zeW1jYi5jb20vdGIuY3JsMB0GA1UdJQQWMBQGCCsG\n" +
//                "AQUFBwMBBggrBgEFBQcDAjBXBggrBgEFBQcBAQRLMEkwHwYIKwYBBQUHMAGGE2h0\n" +
//                "dHA6Ly90Yi5zeW1jZC5jb20wJgYIKwYBBQUHMAKGGmh0dHA6Ly90Yi5zeW1jYi5j\n" +
//                "b20vdGIuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQB2qnnrsAICkV9HNuBdXe+cThHV\n" +
//                "8+5+LBz3zGDpC1rCyq/DIGu0vaa/gasM+MswPj+AEI4f1K1x9K9KedjilVfXH+QI\n" +
//                "tfRzLO8iR0TbPsC6Y1avuXhal1BuvZ9UQayHRDPUEncsf+SHbIOD2GJzXy7vVk5a\n" +
//                "VjkvxLtjMprWIi+P7Hbn2qj03qX9KM1DnNsB28jqg7r2rpXNUPUKsxekfrMTaJgg\n" +
//                "zTnCN/EQvF5eGvAjjHckr1SlogV9o/y4k0x6YmPWR/vopMEPyOj+JhflKCdg+6w3\n" +
//                "79ESvZUhmgT2285c1Nu5vJjtr8x51zCNIpEoVqdkCU4c1aVZGZogSWl1rAIi\n" +
//                "-----END CERTIFICATE-----";



        String certificate = "-----BEGIN CERTIFICATE-----\n"+
                "MIIDGTCCAgGgAwIBAgIJAI1jD1qixIPLMA0GCSqGSIb3DQEBBQUAMCMxITAfBgNV\n"+
                "BAMMGGV2aWxjZXJ0LmRhdGF0aGVvcmVtLmNvbTAeFw0xNTEyMjAxMzU4NDNaFw0y\n"+
                "NTEyMTcxMzU4NDNaMCMxITAfBgNVBAMMGGV2aWxjZXJ0LmRhdGF0aGVvcmVtLmNv\n"+
                "bTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMdltqsRJtO7Nqypkehh\n"+
                "4DSEirp9RM+hJXkBE9nRleTO+utV/snWqX/0wsUrz0wgWyPnAHybGOOXvkrWfXSt\n"+
                "c2/8PyONOeFEU/9S/lWBXGZkaPhgTvkEzPmOOhf06rBMTwXUMGNDI45gKFgkO6Br\n"+
                "bGPeSCuheQj0TKeWdwwNoJ+kczUE06IKu2tcuFRjHXci6VeHjANJzrfKro4ivIRy\n"+
                "bewOGJj1onnpKbui/EOytsmW9MPpOSEXMoVksHOKBQ9nhpL6cDODRvG+t8u7qfFt\n"+
                "mhphemK3IYNMNA4MMXpbJ+Au2hnPApZPEOit34bAwOiGi/batcS3iA+nl06dPYA9\n"+
                "nPkCAwEAAaNQME4wHQYDVR0OBBYEFANxdSXS1JSvjdNtNbYBbRlgii93MB8GA1Ud\n"+
                "IwQYMBaAFANxdSXS1JSvjdNtNbYBbRlgii93MAwGA1UdEwQFMAMBAf8wDQYJKoZI\n"+
                "hvcNAQEFBQADggEBAAM78Bt2aLUgl2Yq4KMIGDeHdWYcRB7QPQ8sp3Q1TOQQzw0i\n"+
                "AukRccl9iYNLgaSJDvlVMapD76jo3okydoWgDogWJhtZpMU/9xegIpukmu5hvF6i\n"+
                "NpqE99PFO5E8BpMkNz+2nskwu//D0as6P9F3tA/o3jC6n6fWX0gt/e9th2ZgVwNQ\n"+
                "9JTH1ZcyFbX9hdBI4xPAtzFX51AsSa8dpRdG+8DmI41Q/1ludoMZboExHldlUbQH\n"+
                "zUuHKF8/T+aNo/9FfpqDz1fFnuoF7tuwyRh73B0YDyDVTNuq7LJ4tmzpVvqIt2tn\n"+
                "RJnQoL4pLQ40SQsoUi4FYG/gxJMoQX6ROWe2nyg=\n"+
                "-----END CERTIFICATE-----";

        X509Certificate mockCert = null;
        ByteArrayInputStream rawCertStream;
        rawCertStream = new ByteArrayInputStream(certificate.getBytes());

        CertificateFactory certificateFactory;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");

            mockCert = (X509Certificate) certificateFactory.generateCertificate(rawCertStream);

        } catch (CertificateException e) {
            TrustKitLog.e(e.getMessage());
        }

        return mockCert;
    }
}


