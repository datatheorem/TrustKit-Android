//package com.datatheorem.android.trustkit.report;
//
//import com.datatheorem.android.trustkit.BuildConfig;
//import com.datatheorem.android.trustkit.report.data.PinFailureReport;
//import com.datatheorem.android.trustkit.report.data.PinFailureReportDiskStore;
//import com.datatheorem.android.trustkit.report.internals.PinFailureReportHttpSender;
//
//import org.junit.After;
//import org.junit.Assert;
//import org.junit.Before;
//import org.junit.Test;
//import org.junit.runner.RunWith;
//import org.mockito.Mock;
//import org.mockito.Mockito;
//import org.mockito.MockitoAnnotations;
//import org.robolectric.Robolectric;
//import org.robolectric.RobolectricTestRunner;
//import org.robolectric.RuntimeEnvironment;
//import org.robolectric.annotation.Config;
//
//import java.net.URL;
//
//import static org.junit.Assert.*;
//
///**
// * TODO:
// * 1. test if the report is sent
// * 2. test if the report is saved
// */
//@Config(constants = BuildConfig.class)
//@RunWith(RobolectricTestRunner.class)
//public class BackgroundReporterTest {
//    private BackgroundReporter backgroundReporter;
//
//    @Mock
//    private PinFailureReportHttpSender mockPinFailureReportHttpSender;
//
//    @Mock
//    private PinFailureReportDiskStore mockPinFailureReportDiskStore;
//
//    @Before
//    public void setUp() throws Exception {
//        MockitoAnnotations.initMocks(this);
//        this.backgroundReporter =
//                new BackgroundReporter(RuntimeEnvironment.application, false,
//                        mockPinFailureReportHttpSender, mockPinFailureReportDiskStore);
//
//
//    }
//
//    @After
//    public void tearDown() throws Exception {
//
//    }
//
//
//    @Test
//    public void testPinValidationFailed() throws Exception {
//        this.backgroundReporter.pinValidationFailed();
//        Mockito.verify(mockPinFailureReportHttpSender).send(new URL("http://www.example.com"),
//                );
//
//
//
//    }
//}