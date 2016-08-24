package com.datatheorem.android.trustkit.report.internals;

import android.os.AsyncTask;

import com.datatheorem.android.trustkit.report.data.PinFailureReport;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;


@SuppressWarnings("unchecked")
public class PinFailureReportHttpSender implements PinFailureReportSender{

    //todo this class should not do pinning
    @Override
    public void send(final URL reportURI, final PinFailureReport pinFailureReport) {

        new AsyncTask() {
            @Override
            protected Object doInBackground(Object[] params) {
                try {

                    HttpURLConnection connection =
                            (HttpURLConnection) reportURI.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/json");
                    connection.setDoOutput(true);
                    connection.setFixedLengthStreamingMode(
                            reportURI.toExternalForm().getBytes("UTF-8").length);

                    connection.connect();

                    final OutputStream outputStream =
                            new BufferedOutputStream(connection.getOutputStream());
                    outputStream.write(
                            pinFailureReport.toJson().toString().getBytes("UTF-8"));
                    outputStream.flush();
                    outputStream.close();

                    connection.disconnect();

                } catch (IOException ioEx) {
                    return ioEx;
                }

                return new Object();
            }

            @Override
            protected void onCancelled() {
                //Log Stuff
                super.onCancelled();
            }

            @Override
            protected void onPostExecute(Object o) {
                if (o instanceof Exception) {
                    TrustKitLog.e("Background upload - task completed with error:" + ((Exception) o).getMessage());
                } else {
                    TrustKitLog.i("Background upload - task completed successfully: pinning failure report sent");
                }
            }
        }.execute();

    }
}
