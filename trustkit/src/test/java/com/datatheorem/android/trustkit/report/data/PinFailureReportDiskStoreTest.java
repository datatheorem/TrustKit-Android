package com.datatheorem.android.trustkit.report.data;

import android.content.Context;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.PinValidationResult;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.io.File;
import java.sql.Date;

import static org.junit.Assert.*;

/**
 * Test if the report-file is saved on the device
 */
@Config(constants = BuildConfig.class)
@RunWith(RobolectricGradleTestRunner.class)
public class PinFailureReportDiskStoreTest {
    private PinFailureReportDiskStore pinFailureReportDiskStore;

    @Mock
    private PinFailureReport pinFailureReport;

    @Before
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);
        pinFailureReportDiskStore =
                new PinFailureReportDiskStore(
                        RuntimeEnvironment.application.getApplicationContext());
    }

    @After
    public void tearDown() throws Exception {}

    @Test
    public void testSave_HappyCase() throws Exception {
        pinFailureReport = new PinFailureReport.Builder()
                .appBundleId("test")
                .appVersion("1.2.3")
                .appPlatform("ANDROID")
                .appVendorId("test")
                .trustKitVersion("4.3.2.1")
                .hostname("other.example.com")
                .port(443)
                .dateTime(new Date(System.currentTimeMillis()))
                .notedHostname("example.com")
                .includeSubdomains(false)
                .enforcePinning(false)
                .validatedCertificateChain(new String[]{"1","2"})
                .knownPins(new String[]{"3","4"})
                .validationResult(new PinValidationResult())
                .build();

        Assert.assertEquals(true,pinFailureReportDiskStore.save(pinFailureReport));
    }

    @Test
    public void testSave_SadCase() throws Exception {
        pinFailureReport = new PinFailureReport.Builder()
                .appBundleId("test")
                .build();
        Assert.assertEquals(false,pinFailureReportDiskStore.save(pinFailureReport));
    }
}