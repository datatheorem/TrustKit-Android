package com.datatheorem.android.trustkit.reporting;

import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.datatheorem.android.trustkit.TestableTrustKit;
import com.datatheorem.android.trustkit.pinning.PinningValidationResult;
import com.datatheorem.android.trustkit.config.PublicKeyPin;
import com.datatheorem.android.trustkit.utils.VendorIdentifier;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Date;
import java.util.ArrayList;
import java.util.HashSet;

import static com.datatheorem.android.trustkit.CertificateUtils.testCertChainPem;
import static junit.framework.Assert.assertEquals;


@RunWith(AndroidJUnit4.class)
public class BackgroundReporterTaskTest {

    private final HashSet<PublicKeyPin> knownPins = new HashSet<PublicKeyPin>() {{
        add(new PublicKeyPin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        add(new PublicKeyPin("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="));
    }};

    private final PinningFailureReport report = new PinningFailureReport("com.unit.test", "1.2",
            VendorIdentifier.getOrCreate(InstrumentationRegistry.getContext()),
            "www.datatheorem.com", 0, "datatheorem.com", true, true,
            testCertChainPem, testCertChainPem, new Date(System.currentTimeMillis()), knownPins,
            PinningValidationResult.FAILED);

    @Before
    public void setUp() {
        TestableTrustKit.reset();
    }

    @Test
    public void testExecuteSucceedHttps() throws MalformedURLException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR1) {
            // TrustKit does not do anything for API level < 17 hence there is no reporting
            return;
        }

        BackgroundReporterTask testTask = new BackgroundReporterTask();

        // Prepare the AsyncTask's arguments
        ArrayList<Object> taskParameters = new ArrayList<>();
        taskParameters.add(report);

        // Add two report URIs with the first one failing, to ensure both are called and last one
        // succeeded
        taskParameters.add(new URL("https://www.google.com/fake"));
        taskParameters.add(new URL("https://overmind.datatheorem.com/trustkit/report"));

        // Run the task synchronously and ensure it succeeded
        Integer lastResponseCode = testTask.doInBackground(taskParameters.toArray());
        assertEquals(Integer.valueOf(200), lastResponseCode);
    }

    @Test
    public void testExecuteSucceedHttp() throws MalformedURLException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR1) {
            // TrustKit does not do anything for API level < 17 hence there is no reporting
            return;
        }

        BackgroundReporterTask testTask = new BackgroundReporterTask();

        // Prepare the AsyncTask's arguments
        ArrayList<Object> taskParameters = new ArrayList<>();
        taskParameters.add(report);

        // Add two report URIs with the first one failing, to ensure both are called and last one
        // succeeded
        taskParameters.add(new URL("http://www.google.com/fake"));
        taskParameters.add(new URL("http://overmind.datatheorem.com/trustkit/report"));

        // Run the task synchronously and ensure it succeeded
        Integer lastResponseCode = testTask.doInBackground(taskParameters.toArray());
        assertEquals(Integer.valueOf(302), lastResponseCode);
    }

    @Test
    public void testExecuteFailedHttpError() throws MalformedURLException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR1) {
            // TrustKit does not do anything for API level < 17 hence there is no reporting
            return;
        }

        BackgroundReporterTask testTask = new BackgroundReporterTask();

        // Prepare the AsyncTask's arguments
        ArrayList<Object> taskParameters = new ArrayList<>();
        taskParameters.add(report);

        // Add two report URIs with the first one succeeding, to ensure both are called
        // and last one failed
        taskParameters.add(new URL("https://overmind.datatheorem.com/trustkit/report"));
        taskParameters.add(new URL("https://www.google.com/fake"));

        // Run the task synchronously and ensure it failed
        Integer lastResponseCode = testTask.doInBackground(taskParameters.toArray());
        assertEquals(Integer.valueOf(404), lastResponseCode);
    }

    @Test
    public void testExecuteFailedNoConnection() throws MalformedURLException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR1) {
            // TrustKit does not do anything for API level < 17 hence there is no reporting
            return;
        }

        BackgroundReporterTask testTask = new BackgroundReporterTask();

        // Prepare the AsyncTask's arguments
        ArrayList<Object> taskParameters = new ArrayList<>();
        taskParameters.add(report);

        taskParameters.add(new URL("https://notareal.domain.datatheorem.com"));

        // Run the task synchronously and ensure it failed silently
        Integer lastResponseCode = testTask.doInBackground(taskParameters.toArray());
        assertEquals(null, lastResponseCode);
    }
}


