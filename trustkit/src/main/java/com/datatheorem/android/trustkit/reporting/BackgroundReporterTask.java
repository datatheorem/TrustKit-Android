package com.datatheorem.android.trustkit.reporting;

import android.os.AsyncTask;

import com.datatheorem.android.trustkit.pinning.SystemTrustManager;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;


// REVIEW(bj): documentation, especially when it will fail to send a report, whether it can retry sending a report, rate
// limiting, etc. (assuming I did not miss these docs somewhere else). Also might be useful to document how the
// reporting functionality differs from the TrustKit-iOS implementation.
//
// Eg, this looks like it behaves different from how Alban had previously described TrustKit-iOS's reporting to me (it
// needs a valid certificate chain, although maybe iOS also only skipped the pinning check; and it looks like it does
// not attempt to perform future retries?)
//
//
// REVIEW(bj): Just to verify, the Async in AsyncTask just means that this class could perform certain events on the UI
// thread (as opposed to a background thread handled by doInBackground()?)
class BackgroundReporterTask extends AsyncTask<Object, Void, Integer> {

    private static final SSLSocketFactory systemSocketFactory = getSystemSSLSocketFactory();

    @Override
    protected final Integer doInBackground(Object... params) {
        Integer lastResponseCode = null;

        // First parameter is the report
        PinningFailureReport report = (PinningFailureReport) params[0];

        // Remaining parameters are report URLs - send the report to each of them
        for (int i=1;i<params.length;i++) {
            URL reportUri = (URL) params[i];
            HttpsURLConnection connection = null;
            try {
                connection = (HttpsURLConnection) reportUri.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setDoOutput(true);
                connection.setChunkedStreamingMode(0);

                // Use the default system factory to ensure we are not doing pinning validation
                // TODO(ad): Test this
                //
                // REVIEW(bj): Is this different from how TrustKit-iOS does its reporting? I thought TK-iOS disabled
                // certificate validation for reporting on the assumption that it is better to report even if the attack
                // sees the report (assuming the attacker isn't sophisticated enough to block the report). Admittedly,
                // requiring a valid certificate combined with retry attempts would eventually allow the report through
                // if it refuses to send to an invalid certificate.
                connection.setSSLSocketFactory(systemSocketFactory);

                connection.connect();

                final OutputStream stream = new BufferedOutputStream(connection.getOutputStream());
                stream.write(report.toJson().toString().getBytes("UTF-8"));
                stream.flush();
                stream.close();

                lastResponseCode = connection.getResponseCode();
            } catch (IOException e) {
                TrustKitLog.i("Background upload - task completed with error:" + e.getMessage());
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }
        return lastResponseCode;
    }

    private static SSLSocketFactory getSystemSSLSocketFactory() {
        SSLContext context;
        try {
            context = SSLContext.getInstance("TLS");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Should never happen");
        }
        if (context == null) {
            throw new IllegalStateException("Should never happen");
        }

        try {
            context.init(null, new TrustManager[] { SystemTrustManager.getInstance() }, null);
        } catch (KeyManagementException e) {
            throw new IllegalStateException("Should never happen");
        }
        return context.getSocketFactory();
    }
}
