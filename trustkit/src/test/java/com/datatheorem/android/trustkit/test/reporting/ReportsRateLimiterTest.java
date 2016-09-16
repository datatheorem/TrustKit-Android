package com.datatheorem.android.trustkit.test.reporting;


import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.pinning.SubjectPublicKeyInfoPin;
import com.datatheorem.android.trustkit.reporting.PinFailureReport;
import com.datatheorem.android.trustkit.reporting.ReportsRateLimiter;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.annotation.Config;

import java.sql.Date;
import java.util.ArrayList;
import java.util.HashSet;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;


@Config(constants = BuildConfig.class)
@RunWith(RobolectricGradleTestRunner.class)
public class ReportsRateLimiterTest {

    private HashSet<SubjectPublicKeyInfoPin> pinList = new HashSet<SubjectPublicKeyInfoPin>() {{
        add(new SubjectPublicKeyInfoPin("rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE="));
        add(new SubjectPublicKeyInfoPin("0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8="));
    }};

    private ArrayList<String> pemCertificateList = new ArrayList<String>() {{
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

        @Test
        public void test() {
            PinFailureReport report = new PinFailureReport("com.test", "1.2.3", "vendorId",
                    BuildConfig.VERSION_NAME, "www.host.com", 443, "host.com", true, true,
                    pemCertificateList, pemCertificateList, new Date(System.currentTimeMillis()),
                    pinList, PinValidationResult.FAILED);

            // Ensure the same report will not be sent twice in a row
            assertFalse(ReportsRateLimiter.shouldRateLimit(report));
            assertTrue(ReportsRateLimiter.shouldRateLimit(report));


            // Set the last time the cache was reset to more than 24 hours ago and ensure the report
            // is sent again
        }
}
