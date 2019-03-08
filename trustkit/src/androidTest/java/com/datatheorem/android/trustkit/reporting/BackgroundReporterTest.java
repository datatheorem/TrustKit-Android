package com.datatheorem.android.trustkit.reporting;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import android.support.v4.content.LocalBroadcastManager;

import com.datatheorem.android.trustkit.TestableTrustKit;
import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.pinning.PinningValidationResult;
import com.datatheorem.android.trustkit.utils.VendorIdentifier;

import org.awaitility.Awaitility;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

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
        Context context = InstrumentationRegistry.getContext();
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

        final PinningValidationReportTestBroadcastReceiver receiver = new PinningValidationReportTestBroadcastReceiver();
        LocalBroadcastManager.getInstance(context)
                .registerReceiver(receiver, new IntentFilter(BackgroundReporter.REPORT_VALIDATION_EVENT));

        TestableBackgroundReporter reporter = new TestableBackgroundReporter( context,
                "com.unit.tests",
                "1.2",
                VendorIdentifier.getOrCreate(context));
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

        validateSentReport(reportSent.getValue());

        Awaitility.await().atMost(2, TimeUnit.SECONDS).untilTrue(receiver.broadcastReceived);
        assertTrue(receiver.broadcastReceived.get());
        assertTrue(receiver.containedReport instanceof PinningFailureReport);
        validateSentReport((PinningFailureReport) receiver.containedReport);
    }

    private void validateSentReport(PinningFailureReport reportSent) throws JSONException {
        // Validate the content of the generated report
        JSONObject reportSentJson = reportSent.toJson();
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
        ArrayList<String> pinsTestable = new ArrayList<>();
        for (int i = 0; i < knownPins.length(); i++) {
            pinsTestable.add(knownPins.getString(i));
        }
        assertEquals(2, knownPins.length());
        assertTrue(pinsTestable
            .contains("pin-sha256=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\""));
        assertTrue(pinsTestable
            .contains("pin-sha256=\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\""));
    }

    private class PinningValidationReportTestBroadcastReceiver extends BroadcastReceiver{
        public AtomicBoolean broadcastReceived = new AtomicBoolean(false);
        public Serializable containedReport;

        @Override
        public void onReceive(Context context, Intent intent) {
            broadcastReceived.set(true);
            containedReport = intent.getSerializableExtra(BackgroundReporter.EXTRA_REPORT);
        }
    }
}


