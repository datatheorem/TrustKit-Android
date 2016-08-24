package com.datatheorem.android.trustkit.report;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.support.v4.content.LocalBroadcastManager;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.TrustKit;

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

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        context = RuntimeEnvironment.application.getApplicationContext();
        TrustKit.init(context, null);
        this.backgroundReporter = new BackgroundReporter(false, "test-id");
        mockBroadcastReceiver = new MockBroadcastReceiver();
        LocalBroadcastManager.getInstance(context)
                .registerReceiver(mockBroadcastReceiver, new IntentFilter("test-id"));
        server = new MockWebServer();
        server.start();
    }

    @After
    public void tearDown() throws Exception {
        server.shutdown();
    }


    /*
     * We test the three results of a pinValidationFailed call
     */
    @Test
    public void testPinValidationFailed() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200));
        server.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
                return new MockResponse().setBody(request.getBody());
            }
        });
        Assert.assertEquals(false, mockBroadcastReceiver.received);

        HttpUrl baseUrl = server.url("/report");

        backgroundReporter.pinValidationFailed("www.test.com", 443, new String[]{""},
                "www.test.com", new String[] {baseUrl.toString()}, false, true, new String[]{""},
                new PinValidationResult());

        RecordedRequest request = server.takeRequest();
        //Check if the request is well formed
        Assert.assertEquals("/report", request.getPath());
        Assert.assertEquals("POST", request.getMethod());
        Assert.assertEquals(true, request.getBody().readUtf8Line().startsWith("{\"trustkit-version"));

        //Check if the report is sent through the system
        Assert.assertEquals(true, mockBroadcastReceiver.received);

        //Check if the report file is created on the system
        Assert.assertEquals(true, new File(context.getFilesDir() + File.separator + "tmp"
                + File.separator + "0.tsk-report").exists());
    }


    public class MockBroadcastReceiver extends BroadcastReceiver {
        public boolean received = false;
        public PinFailureReport pinFailureReport = null;
        @Override
        public void onReceive(Context context, Intent intent) {
            received = true;
            pinFailureReport =
                    (PinFailureReport) intent.getExtras().getSerializable("report");
        }
    }
}


