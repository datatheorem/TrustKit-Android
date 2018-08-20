package com.datatheorem.android.trustkit.config;


import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

import android.support.test.runner.AndroidJUnit4;
import com.datatheorem.android.trustkit.CertificateUtils;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import org.junit.Test;
import org.junit.runner.RunWith;


@RunWith(AndroidJUnit4.class)
public class PublicKeyPinTest {

    @Test
    public void testFromCertificate() throws CertificateException {
        String pemCertificate =
                "MIIDGTCCAgGgAwIBAgIJAI1jD1qixIPLMA0GCSqGSIb3DQEBBQUAMCMxITAfBgNV\n" +
                "BAMMGGV2aWxjZXJ0LmRhdGF0aGVvcmVtLmNvbTAeFw0xNTEyMjAxMzU4NDNaFw0y\n" +
                "NTEyMTcxMzU4NDNaMCMxITAfBgNVBAMMGGV2aWxjZXJ0LmRhdGF0aGVvcmVtLmNv\n" +
                "bTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMdltqsRJtO7Nqypkehh\n" +
                "4DSEirp9RM+hJXkBE9nRleTO+utV/snWqX/0wsUrz0wgWyPnAHybGOOXvkrWfXSt\n" +
                "c2/8PyONOeFEU/9S/lWBXGZkaPhgTvkEzPmOOhf06rBMTwXUMGNDI45gKFgkO6Br\n" +
                "bGPeSCuheQj0TKeWdwwNoJ+kczUE06IKu2tcuFRjHXci6VeHjANJzrfKro4ivIRy\n" +
                "bewOGJj1onnpKbui/EOytsmW9MPpOSEXMoVksHOKBQ9nhpL6cDODRvG+t8u7qfFt\n" +
                "mhphemK3IYNMNA4MMXpbJ+Au2hnPApZPEOit34bAwOiGi/batcS3iA+nl06dPYA9\n" +
                "nPkCAwEAAaNQME4wHQYDVR0OBBYEFANxdSXS1JSvjdNtNbYBbRlgii93MB8GA1Ud\n" +
                "IwQYMBaAFANxdSXS1JSvjdNtNbYBbRlgii93MAwGA1UdEwQFMAMBAf8wDQYJKoZI\n" +
                "hvcNAQEFBQADggEBAAM78Bt2aLUgl2Yq4KMIGDeHdWYcRB7QPQ8sp3Q1TOQQzw0i\n" +
                "AukRccl9iYNLgaSJDvlVMapD76jo3okydoWgDogWJhtZpMU/9xegIpukmu5hvF6i\n" +
                "NpqE99PFO5E8BpMkNz+2nskwu//D0as6P9F3tA/o3jC6n6fWX0gt/e9th2ZgVwNQ\n" +
                "9JTH1ZcyFbX9hdBI4xPAtzFX51AsSa8dpRdG+8DmI41Q/1ludoMZboExHldlUbQH\n" +
                "zUuHKF8/T+aNo/9FfpqDz1fFnuoF7tuwyRh73B0YDyDVTNuq7LJ4tmzpVvqIt2tn\n" +
                "RJnQoL4pLQ40SQsoUi4FYG/gxJMoQX6ROWe2nyg=";
        Certificate cert = CertificateUtils.certificateFromPem(pemCertificate);
        PublicKeyPin pin = new PublicKeyPin(cert);
        assertEquals("Ckvh+UFO2eHunqaB2w0jsrwrJJQcSoES+p9FUhVoszQ=", pin.toString());
    }

    @Test
    public void testFromString() {
        PublicKeyPin pin =
                new PublicKeyPin("rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=");
        assertEquals(pin.toString(),"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=");
    }

    @Test
    public void testFromBadStringNotBase64() {
        boolean didReturnError = false;
        try {
            new PublicKeyPin("rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIh!5dn4oCeE=");
        } catch (IllegalArgumentException e) {
            if (e.getMessage().startsWith("bad base-64")) {
                didReturnError = true;
            }
            else {
                throw e;
            }
        }
        assertTrue(didReturnError);
    }

    @Test
    public void testFromBadStringBadLength() {
        boolean didReturnError = false;
        try {
            new PublicKeyPin("ZW5jb2U=");
        } catch (IllegalArgumentException e) {
            if (e.getMessage().startsWith("Invalid pin")) {
                didReturnError = true;
            }
            else {
                throw e;
            }
        }
        assertTrue(didReturnError);
    }
}
