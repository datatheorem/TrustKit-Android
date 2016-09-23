package com.datatheorem.android.trustkit.reporting;


import android.os.AsyncTask;
import android.util.Base64;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.pinning.TrustKitTrustManagerBuilder;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;


/**
 * The BackgroundReporter save a report when a pinning validation fail and send the report
 * to the specific URI.
 */
public class BackgroundReporter {



    // Main application environment information
    private final String appPackageName;
    private final String appVersion;
    private final String appVendorId;

    // Configuration and Objects managing all the operation done by the BackgroundReporter
    private final boolean shouldRateLimitsReports;

    public BackgroundReporter(boolean shouldRateLimitsReports, String appPackageName,
                              String appVersion, String appVendorId) {
        this.shouldRateLimitsReports = shouldRateLimitsReports;
        this.appPackageName = appPackageName;
        this.appVersion = appVersion;
        this.appVendorId = appVendorId;
    }

    private static String certificateToPem(X509Certificate certificate) {
        byte[] certificateData;
        try {
            certificateData = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Should never happen - certificate was previously " +
                    "parsed by the system");
        }

        // Create the PEM string
        String certificateAsPem = "-----BEGIN CERTIFICATE-----\n";
        certificateAsPem += Base64.encodeToString(certificateData, Base64.DEFAULT);
        certificateAsPem += "-----END CERTIFICATE-----\n";
        return certificateAsPem;
    }


    public void pinValidationFailed(String serverHostname,
                                    Integer serverPort,
                                    List<X509Certificate> servedCertificateChain,
                                    List<X509Certificate> validatedCertificateChain,
                                    DomainPinningPolicy serverConfig,
                                    PinValidationResult validationResult) {

        TrustKitLog.i("Generating pin failure report for " + serverHostname);

        // Convert the certificates to PEM strings
        ArrayList<String> validatedCertificateChainAsPem = new ArrayList<>();
        for (X509Certificate certificate : validatedCertificateChain) {
            validatedCertificateChainAsPem.add(certificateToPem(certificate));
        }
        ArrayList<String> servedCertificateChainAsPem = new ArrayList<>();
        for (X509Certificate certificate : servedCertificateChain) {
            servedCertificateChainAsPem.add(certificateToPem(certificate));
        }

        // Generate the corresponding pin failure report
        final PinFailureReport report = new PinFailureReport(appPackageName, appVersion,
                appVendorId, BuildConfig.VERSION_NAME, serverHostname, serverPort,
                serverConfig.getHostname(), serverConfig.shouldIncludeSubdomains(),
                serverConfig.shouldEnforcePinning(), servedCertificateChainAsPem,
                validatedCertificateChainAsPem, new Date(System.currentTimeMillis()),
                serverConfig.getPublicKeyHashes(), validationResult);

        // If a similar report hasn't been sent recently, send it now
        if (shouldRateLimitsReports && ReportsRateLimiter.shouldRateLimit(report)) {
            TrustKitLog.i("Pin failure report for " + serverHostname
                    + " was not sent due to rate-limiting");
            return;
        }

        new AsyncTask<HashSet<URL>, Void, Void>() {
            private int responseCode = -1;

            int getResponseCode() {
                return responseCode;
            }

            @SafeVarargs
            @Override
            protected final Void doInBackground(HashSet<URL>... params) {
                for (final URL reportUri : params[0]) {

                    HttpsURLConnection connection = null;
                    try {
                        connection = (HttpsURLConnection) reportUri.openConnection();
                        connection.setRequestMethod("POST");
                        connection.setRequestProperty("Content-Type", "application/json");
                        connection.setDoOutput(true);
                        connection.setChunkedStreamingMode(0);

                        // Use the default system factory to ensure we are not doing pinning validation
                        // TODO(ad): Test this
                        connection.setSSLSocketFactory(getSystemSSLSocketFactory());

                        connection.connect();

                        final OutputStream stream =
                                new BufferedOutputStream(connection.getOutputStream());
                        stream.write(report.toJson().toString().getBytes("UTF-8"));
                        stream.flush();
                        stream.close();

                        responseCode = connection.getResponseCode();
                    } catch (IOException e) {
                        TrustKitLog.e("Background upload - task completed with error:"
                                + e.getMessage());
                    } finally {
                        if (connection != null) {
                            connection.disconnect();
                        }
                    }
                }
                return null;
            }

            @Override
            protected void onPostExecute(Void aVoid) {
                if (this.getResponseCode() >= 200 && this.getResponseCode() < 300) {
                    TrustKitLog.i("Background upload - task completed successfully: pinning " +
                            "failure report sent");
                } else {
                    TrustKitLog.e("Background upload - task completed with error: connection" +
                            " error");
                }
            }

        }.execute((HashSet<URL>) serverConfig.getReportUris());
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
            // Get a trust manager for an empty hostname so we get a non-pinning trust manager
            context.init(null, new TrustManager[] {TrustKitTrustManagerBuilder.getTrustManager("")}, null);
        } catch (KeyManagementException e) {
            throw new IllegalStateException("Should never happen");
        }
        return context.getSocketFactory();
    }

}
