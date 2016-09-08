package com.datatheorem.android.trustkit.reporting;

import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;


class PinFailureReportHttpSender{
    private int responseCode = -1;

    //todo this class should not do pinning
    public void send(final URL reportURI, final PinFailureReport pinFailureReport) {

        HttpURLConnection connection = null;
        try {

            connection = (HttpURLConnection) reportURI.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            connection.setChunkedStreamingMode(0);
            connection.connect();

            final OutputStream stream = new BufferedOutputStream(connection.getOutputStream());
            stream.write(pinFailureReport.toJson().toString().getBytes("UTF-8"));
            stream.flush();
            stream.close();

            responseCode = connection.getResponseCode();
        } catch (IOException ioEx) {
            TrustKitLog.e("Background upload - task completed with error:" +
                    ioEx.getMessage());

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
