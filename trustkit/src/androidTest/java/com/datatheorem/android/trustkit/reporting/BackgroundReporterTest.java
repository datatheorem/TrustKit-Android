package com.datatheorem.android.trustkit.reporting;

import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.datatheorem.android.trustkit.TestableTrustKit;
import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.pinning.PinningValidationResult;
import com.datatheorem.android.trustkit.utils.VendorIdentifier;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;

import static com.datatheorem.android.trustkit.CertificateUtils.testCertChain;
import static com.datatheorem.android.trustkit.CertificateUtils.testCertChainPem;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;


@RunWith(AndroidJUnit4.class)
public class BackgroundReporterTest {

    @Before
    public void setUp() {
        TestableTrustKit.reset();
    }

    @Test
    public void testPinValidationFailed() throws MalformedURLException, JSONException {
        if (Build.VERSION.SDK_INT < 17) {
            // TrustKit does not do anything for API level < 17 hence there is no reporting
            return;
        }

        // Initialize TrustKit
        String serverHostname = "mail.google.com";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname("google.com")
                .setShouldIncludeSubdomains(true)
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }})
                .setShouldDisableDefaultReportUri(true)
                .setReportUris(new HashSet<String>() {{ add("https://overmind.datatheorem.com"); }})
                .build();

        TestableBackgroundReporter reporter = new TestableBackgroundReporter("com.unit.tests",
                "1.2",
                VendorIdentifier.getOrCreate(InstrumentationRegistry.getContext()));
        TestableBackgroundReporter reporterSpy = Mockito.spy(reporter);

        // Call the method twice to also test the report rate limiter
        reporterSpy.pinValidationFailed(serverHostname, 443, testCertChain, testCertChain,
                domainPolicy, PinningValidationResult.FAILED);
        reporterSpy.pinValidationFailed(serverHostname, 443, testCertChain, testCertChain,
                domainPolicy, PinningValidationResult.FAILED);

        ArgumentCaptor<PinningFailureReport> reportSent =
                ArgumentCaptor.forClass(PinningFailureReport.class);

        // Ensure the sendReport() method was only called once, to make sure the rate limiter
        // blocked the second, identical report
        verify(reporterSpy, times(1)).sendReport(
                reportSent.capture(),
                eq(new HashSet<URL>() {{ add(new URL("https://overmind.datatheorem.com")); }} )
        );

        // Validate the content of the generated report
        JSONObject reportSentJson = reportSent.getValue().toJson();
        assertEquals("com.unit.tests", reportSentJson.getString("app-bundle-id"));
        assertEquals("1.2", reportSentJson.getString("app-version"));
        assertEquals("ANDROID", reportSentJson.getString("app-platform"));
        assertEquals("mail.google.com", reportSentJson.getString("hostname"));
        assertEquals("google.com", reportSentJson.getString("noted-hostname"));
        assertEquals(443, reportSentJson.getInt("port"));
        assertTrue(reportSentJson.getBoolean("include-subdomains"));
        assertTrue(reportSentJson.getBoolean("enforce-pinning"));
        assertEquals(PinningValidationResult.FAILED.ordinal(),
                reportSentJson.getInt("validation-result"));
        assertEquals("google.com", reportSentJson.getString("noted-hostname"));

        assertNotNull(reportSentJson.getString("app-vendor-id"));
        assertNotNull(reportSentJson.getString("trustkit-version"));
        assertNotNull(reportSentJson.getString("date-time"));

        JSONArray validatedChain = reportSentJson.getJSONArray("validated-certificate-chain");
        assertEquals(2, validatedChain.length());
        assertEquals(testCertChainPem.get(0).replace("\n", ""),
                validatedChain.getString(0).replace("\n", ""));
        assertEquals(testCertChainPem.get(1).replace("\n", ""),
                validatedChain.getString(1).replace("\n", ""));

        JSONArray servedChain = reportSentJson.getJSONArray("served-certificate-chain");
        assertEquals(2, servedChain.length());
        assertEquals(testCertChainPem.get(0).replace("\n", ""),
                servedChain.getString(0).replace("\n", ""));
        assertEquals(testCertChainPem.get(1).replace("\n", ""),
                servedChain.getString(1).replace("\n", ""));

        JSONArray knownPins = reportSentJson.getJSONArray("known-pins");
        assertEquals(2, knownPins.length());
        assertEquals("pin-sha256=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"",
                knownPins.getString(0));
        assertEquals("pin-sha256=\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\"",
                knownPins.getString(1));
    }
}


