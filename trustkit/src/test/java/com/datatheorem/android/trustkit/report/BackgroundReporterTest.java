package com.datatheorem.android.trustkit.report;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.report.data.PinFailureReport;
import com.datatheorem.android.trustkit.report.data.PinFailureReportDiskStore;
import com.datatheorem.android.trustkit.report.internals.PinFailureReportHttpSender;
import com.datatheorem.android.trustkit.report.internals.PinFailureReportInternalSender;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

import java.net.URL;
import java.util.concurrent.CountDownLatch;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

/**
 * TODO:
 * 1. test if the BackgroundReporter calls a sender
 * 2. test if the BackgrounReporter calls a local saver
 */
@Config(constants = BuildConfig.class)
@RunWith(RobolectricGradleTestRunner.class)
public class BackgroundReporterTest {
    private BackgroundReporter backgroundReporter;

    @Mock
    private PinFailureReportHttpSender mockPinFailureReportHttpSender;

    @Mock
    private PinFailureReportInternalSender mockPinFailureReportInternalSender;

    @Mock
    private PinFailureReportDiskStore mockPinFailureReportDiskStore;


    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        TrustKit.init(RuntimeEnvironment.application.getApplicationContext(), null);
        this.backgroundReporter =
                new BackgroundReporter(false, mockPinFailureReportDiskStore,
                        mockPinFailureReportHttpSender, mockPinFailureReportInternalSender);
    }

    @After
    public void tearDown() throws Exception {}


    @Test
    public void testPinValidationFailed() throws Exception {
        String reportUri = "http://requestb.in/1gsqdmo1";

        this.backgroundReporter.pinValidationFailed("www.test.com", null, null,  "www.test.com",
                new String[] {reportUri}, false, true, null, null);

        Mockito.verify(mockPinFailureReportHttpSender)
                .send(eq(new URL(reportUri)), any(PinFailureReport.class));
        Mockito.verify(mockPinFailureReportDiskStore).save(any(PinFailureReport.class));
        Mockito.verify(mockPinFailureReportInternalSender)
                .send((URL) eq(null), any(PinFailureReport.class));
    }
}