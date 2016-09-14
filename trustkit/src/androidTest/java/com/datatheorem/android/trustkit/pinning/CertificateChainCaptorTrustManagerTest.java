package com.datatheorem.android.trustkit.pinning;


import org.junit.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;


public class CertificateChainCaptorTrustManagerTest {

    @Test
    public void someConnection() {
        URL url;
        HttpsURLConnection urlConnection = null;
        try {
            url = new URL("https://www.google.com/");
            urlConnection = (HttpsURLConnection) url.openConnection();
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{new CertificateChainCaptorTrustManager()}, null);
            urlConnection.setSSLSocketFactory(context.getSocketFactory());

            InputStream in = urlConnection.getInputStream();
            InputStreamReader isw = new InputStreamReader(in);

            int data = isw.read();
            while (data != -1) {
                char current = (char) data;
                data = isw.read();
                System.out.print(current);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (urlConnection != null) {
                urlConnection.disconnect();
            }
        }
    }

}
