package com.datatheorem.android.trustkit.report;

import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;


@SuppressWarnings("unchecked")
class PinFailureReportHttpSender implements PinFailureReportSender{
    private int responseCode = -1;

    //todo this class should not do pinning
    @Override
    public void send(final URL reportURI, final PinFailureReport pinFailureReport) {

        HttpURLConnection connection = null;
        try {

            connection =
                    (HttpURLConnection) reportURI.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            connection.setChunkedStreamingMode(0);
            connection.connect();

            final OutputStream outputStream =
                    new BufferedOutputStream(connection.getOutputStream());
            outputStream.write(
                    pinFailureReport.toJson().toString().getBytes("UTF-8"));
            outputStream.flush();
            outputStream.close();

            responseCode = connection.getResponseCode();
        } catch (IOException ioEx) {
            TrustKitLog.e("Background upload - task completed with error:" +
                    ioEx.getMessage());

        } finally {
            if (connection != null) {
                connection.disconnect();
                TrustKitLog.i("Background upload - task completed successfully: pinning failure " +
                        "report sent");
            } else {
                TrustKitLog.e("Background upload - task completed with error: connection error");
            }
        }

    }

    public int getResponseCode() {
        return responseCode;
    }
}
