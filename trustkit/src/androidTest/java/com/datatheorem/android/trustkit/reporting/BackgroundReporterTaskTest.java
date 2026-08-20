package com.datatheorem.android.trustkit.reporting;

import static com.datatheorem.android.trustkit.CertificateUtils.testCertChainPem;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNull;

import android.os.Build;
import androidx.test.platform.app.InstrumentationRegistry;
import com.datatheorem.android.trustkit.TestableTrustKit;
import com.datatheorem.android.trustkit.config.PublicKeyPin;
import com.datatheorem.android.trustkit.pinning.PinningValidationResult;
import com.datatheorem.android.trustkit.utils.VendorIdentifier;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.sql.Date;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;

public class BackgroundReporterTaskTest {

    private final HashSet<PublicKeyPin> knownPins =
            new HashSet<PublicKeyPin>() {
                {
                    add(new PublicKeyPin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
                    add(new PublicKeyPin("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="));
                }
            };

    private final PinningFailureReport report =
            new PinningFailureReport(
                    "com.unit.test",
                    "1.2",
                    VendorIdentifier.getOrCreate(
                            InstrumentationRegistry.getInstrumentation().getContext()),
                    "www.datatheorem.com",
                    0,
                    "datatheorem.com",
                    true,
                    true,
                    testCertChainPem,
                    testCertChainPem,
                    new Date(System.currentTimeMillis()),
                    knownPins,
                    PinningValidationResult.FAILED);

    @Before
    public void setUp() {
        TestableTrustKit.reset();
    }

    @Test
    public void testExecuteSucceedHttps() throws MalformedURLException {
        if (Build.VERSION.SDK_INT < 17) {
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
        if (Build.VERSION.SDK_INT < 17) {
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
        assertEquals(Integer.valueOf(200), lastResponseCode);
    }

    @Test
    public void testExecuteFailedHttpError() throws MalformedURLException {
        if (Build.VERSION.SDK_INT < 17) {
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
        if (Build.VERSION.SDK_INT < 17) {
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

    @Test
    public void testConfiguredHeadersAreScopedToDefaultReportUrl() throws Exception {
        RecordingUrlStreamHandler configuredHandler = new RecordingUrlStreamHandler();
        URL configuredUrl =
                new URL(null, "http://configured.example.com/report", configuredHandler);
        RecordingUrlStreamHandler xmlHandler = new RecordingUrlStreamHandler();
        URL xmlUrl = new URL(null, "http://xml.example.com/report", xmlHandler);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer secret");
        headers.put("X-Report-Client", "test-client");
        BackgroundReporterTask testTask = new BackgroundReporterTask(configuredUrl, headers);

        Integer responseCode = testTask.doInBackground(report, configuredUrl, xmlUrl);

        assertEquals(Integer.valueOf(200), responseCode);
        assertEquals(
                "Bearer secret",
                configuredHandler.connection.getRecordedRequestProperty("Authorization"));
        assertEquals(
                "test-client",
                configuredHandler.connection.getRecordedRequestProperty("X-Report-Client"));
        assertNull(xmlHandler.connection.getRecordedRequestProperty("Authorization"));
        assertNull(xmlHandler.connection.getRecordedRequestProperty("X-Report-Client"));
    }

    @Test
    public void testConfiguredAuthorizationOverridesUrlBasicAuthentication() throws Exception {
        RecordingUrlStreamHandler handler = new RecordingUrlStreamHandler();
        URL configuredUrl =
                new URL(null, "http://user:password@configured.example.com/report", handler);
        Map<String, String> headers = Collections.singletonMap("Authorization", "Bearer secret");
        BackgroundReporterTask testTask = new BackgroundReporterTask(configuredUrl, headers);

        testTask.doInBackground(report, configuredUrl);

        assertEquals(
                "Bearer secret", handler.connection.getRecordedRequestProperty("Authorization"));
    }

    private static final class RecordingUrlStreamHandler extends URLStreamHandler {
        private RecordingHttpURLConnection connection;

        @Override
        protected URLConnection openConnection(URL url) {
            connection = new RecordingHttpURLConnection(url);
            return connection;
        }
    }

    private static final class RecordingHttpURLConnection extends HttpURLConnection {
        private final Map<String, String> requestProperties = new LinkedHashMap<>();
        private final ByteArrayOutputStream requestBody = new ByteArrayOutputStream();

        RecordingHttpURLConnection(URL url) {
            super(url);
        }

        @Override
        public void setRequestProperty(String key, String value) {
            requestProperties.put(key, value);
        }

        String getRecordedRequestProperty(String key) {
            return requestProperties.get(key);
        }

        @Override
        public OutputStream getOutputStream() {
            return requestBody;
        }

        @Override
        public int getResponseCode() {
            return 200;
        }

        @Override
        public void disconnect() {}

        @Override
        public boolean usingProxy() {
            return false;
        }

        @Override
        public void connect() throws IOException {
            connected = true;
        }
    }
}
