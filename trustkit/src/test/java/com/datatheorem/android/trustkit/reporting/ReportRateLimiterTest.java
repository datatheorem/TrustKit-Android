package com.datatheorem.android.trustkit.reporting;


import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.pinning.PublicKeyPin;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.annotation.Config;

import java.util.Date;
import java.util.ArrayList;
import java.util.HashSet;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;


@Config(constants = BuildConfig.class)
@RunWith(RobolectricGradleTestRunner.class)
public class ReportRateLimiterTest {

    private HashSet<PublicKeyPin> pinList = new HashSet<PublicKeyPin>() {{
        add(new PublicKeyPin("rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE="));
        add(new PublicKeyPin("0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="));
    }};

    private ArrayList<String> pemCertificateList1 = new ArrayList<String>() {{
        add("-----BEGIN CERTIFICATE-----\n"+
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
                "-----END CERTIFICATE-----");
    }};

    private ArrayList<String> pemCertificateList2 = new ArrayList<String>() {{
        add("-----BEGIN CERTIFICATE-----\n" +
                "MIIE2TCCA8GgAwIBAgIQFVDTs9tHXX3ivhstjNW2zANBgkqhkiG9w0BAQUFADA8\n" +
                "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMVGhhd3RlLCBJbmMuMRYwFAYDVQQDEw1U\n" +
                "aGF3dGUgU1NMIENBMB4XDTE0MTAwMjAwMDAwMFoXDTE1MTEwMTIzNTk1OVowgZcx\n" +
                "CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQHFAlQYWxv\n" +
                "IEFsdG8xGzAZBgNVBAoUEkRhdGEgVGhlb3JlbSwgSW5jLjEkMCIGA1UECxQbU2Nh\n" +
                "biBhbmQgU2VjdXJlIE1vYmlsZSBBcHBzMRwwGgYDVQQDFBN3d3cuZGF0YXRoZW9y\n" +
                "ZW0uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5bCuLK3XOnNs\n" +
                "i8CJvHU4H5yY3d4G1qzq7EeMydKuScMM8Nqsp4CySKTbrUhi/uIc08II9yBxM+q4\n" +
                "NmrEg0tgVvTqvUjmMN/MrYQrSGVLxPq5gadI7UxfWeGSo9DpvgXaw1Vvehs2jGFK\n" +
                "jLzDYbzJOhv/pqpv4UCV/xfeuqmTNqqzsp+tB5Zn6gXIvIFsxfpjbeId4OWviLnC\n" +
                "q957++coddvqBZd2sWkyzE2un5itXRKfnMGSBTB0cU9/9fXeGhzA+u01Xj+BfpHR\n" +
                "uP/eX+rHsgc3a4hbsSWDG5278ujJ5+4To9Bn/rTZy7uALTM2oBZvsFX4567RhB1\n" +
                "IYbMDE5y8QIDAQABo4IBeTCCAXUwHgYDVR0RBBcwFYITd3d3LmRhdGF0aGVvcmVt\n" +
                "LmNvbTAJBgNVHRMEAjAAMHIGA1UdIARrMGkwZwYKYIZIAYb4RQEHNjBZMCYGCCsG\n" +
                "AQUFBwIBFhpodHRwczovL3d3dy50aGF3dGUuY29tL2NwczAvBggrBgEFBQcCAjAj\n" +
                "DCFodHRwczovL3d3dy50aGF3dGUuY29tL3JlcG9zaXRvcnkwDgYDVR0PAQH/BAQD\n" +
                "AgWgMB8GA1UdIwQYMBaAFKeig7s0RUA9/NUwTxK5PqEBn/bbMCsGA1UdHwQkMCIw\n" +
                "IKAeoByGGmh0dHA6Ly90Yi5zeW1jYi5jb20vdGIuY3JsMB0GA1UdJQQWMBQGCCsG\n" +
                "AQUFBwMBBggrBgEFBQcDAjBXBggrBgEFBQcBAQRLMEkwHwYIKwYBBQUHMAGGE2h0\n" +
                "dHA6Ly90Yi5zeW1jZC5jb20wJgYIKwYBBQUHMAKGGmh0dHA6Ly90Yi5zeW1jYi5j\n" +
                "b20vdGIuY3J0MA0GCSqGSIb3DQEBBQUAA4IBAQB2qnnrsAICkV9HNuBdXe+cThHV\n" +
                "8+5+LBz3zGDpC1rCyq/DIGu0vaa/gasM+MswPj+AEI4f1K1x9K9KedjilVfXH+QI\n" +
                "tfRzLO8iR0TbPsC6Y1avuXhal1BuvZ9UQayHRDPUEncsf+SHbIOD2GJzXy7vVk5a\n" +
                "VjkvxLtjMprWIi+P7Hbn2qj03qX9KM1DnNsB28jqg7r2rpXNUPUKsxekfrMTaJgg\n" +
                "zTnCN/EQvF5eGvAjjHckr1SlogV9o/y4k0x6YmPWR/vopMEPyOj+JhflKCdg+6w3\n" +
                "79ESvZUhmgT2285c1Nu5vJjtr8x51zCNIpEoVqdkCU4c1aVZGZogSWl1rAIi\n" +
                "-----END CERTIFICATE-----");
    }};


    @Test
    public void test() {
        PinningFailureReport report = new PinningFailureReport("com.test", "1.2.3", "vendorId",
                BuildConfig.VERSION_NAME, "www.host.com", 443, "host.com", true, true,
                pemCertificateList1, pemCertificateList1, new Date(),
                pinList, PinValidationResult.FAILED);

        // Ensure the same report will not be sent twice in a row
        assertFalse(ReportRateLimiter.shouldRateLimit(report));
        assertTrue(ReportRateLimiter.shouldRateLimit(report));

        // Set the last time the cache was reset to more than 24 hours ago and ensure the report
        // is sent again
        long oneDayAgo = System.currentTimeMillis()-25*60*60*1000;
        TestableReportRateLimiter.setLastReportsCacheResetDate(new Date(oneDayAgo));
        assertFalse(ReportRateLimiter.shouldRateLimit(report));
        assertTrue(ReportRateLimiter.shouldRateLimit(report));


        // Ensure the same report with a different validation result will be sent
        report = new PinningFailureReport("com.test", "1.2.3", "vendorId",
                BuildConfig.VERSION_NAME, "www.host.com", 443, "host.com", true, true,
                pemCertificateList1, pemCertificateList1, new Date(),
                pinList, PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED);
        assertFalse(ReportRateLimiter.shouldRateLimit(report));
        assertTrue(ReportRateLimiter.shouldRateLimit(report));

        // Ensure the same report with a different hostname will be sent
        report = new PinningFailureReport("com.test", "1.2.3", "vendorId",
                BuildConfig.VERSION_NAME, "www.otherhost.com", 443, "host.com", true, true,
                pemCertificateList1, pemCertificateList1, new Date(),
                pinList, PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED);
        assertFalse(ReportRateLimiter.shouldRateLimit(report));
        assertTrue(ReportRateLimiter.shouldRateLimit(report));


        // Ensure the same report with a different certificate chain will be sent
        report = new PinningFailureReport("com.test", "1.2.3", "vendorId",
                BuildConfig.VERSION_NAME, "www.otherhost.com", 443, "host.com", true, true,
                pemCertificateList2, pemCertificateList2, new Date(),
                pinList, PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED);
        assertFalse(ReportRateLimiter.shouldRateLimit(report));
        assertTrue(ReportRateLimiter.shouldRateLimit(report));
    }
}
