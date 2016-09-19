package com.datatheorem.android.trustkit.reporting;

import com.datatheorem.android.trustkit.pinning.PinningTrustManager;
import com.datatheorem.android.trustkit.utils.TrustKitLog;
import com.google.common.annotations.Beta;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

// TODO(ad): Merge this into the AsyncTask
class PinFailureReportHttpSender {

    // Use the default SSL socket factory to not do pinning validation when sending reports
    private static final SSLSocketFactory systemSSLSocketFactory;
    static {
        SSLContext context = null;
        try {
            context = SSLContext.getInstance("TLS");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Should never happen");
        }
        if (context == null) {
            throw new IllegalStateException("Should never happen");
        }

        try {
            context.init(null, new TrustManager[] {PinningTrustManager.getSystemTrustManager()},
                    null);
        } catch (KeyManagementException e) {
            throw new IllegalStateException("Should never happen");
        }
        systemSSLSocketFactory = context.getSocketFactory();
    }

    private int responseCode = -1;

    public void send(final URL reportURI, final PinFailureReport pinFailureReport) {

        HttpsURLConnection connection = null;
        try {
            connection = (HttpsURLConnection) reportURI.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);
            connection.setChunkedStreamingMode(0);

            // Use the default system factory to ensure we are not doing pinning validation
            // TODO(ad): Test this
            connection.setSSLSocketFactory(systemSSLSocketFactory);

            connection.connect();

            final OutputStream stream = new BufferedOutputStream(connection.getOutputStream());
            stream.write(pinFailureReport.toJson().toString().getBytes("UTF-8"));
            stream.flush();
            stream.close();

            responseCode = connection.getResponseCode();

        } catch (IOException e) {
            TrustKitLog.e("Background upload - task completed with error:" + e.getMessage());

        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public int getResponseCode() {
        return responseCode;
    }
}
