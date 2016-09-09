package com.datatheorem.android.trustkit.pinning;



import android.net.SSLCertificateSocketFactory;
import android.support.test.filters.SmallTest;
import android.support.test.runner.AndroidJUnit4;
import android.util.Log;

import com.datatheorem.android.trustkit.BuildConfig;

import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;

import javax.net.SocketFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;


@RunWith(AndroidJUnit4.class)
@SmallTest
public class PinningSSLSocketFactoryTest {

    @Test
    public void someConnection() {
        URL url;
        HttpsURLConnection urlConnection = null;
        try {
            url = new URL("https://wrong.host.badssl.com/");
            //url = new URL("https://expired.badssl.com/");
            urlConnection = (HttpsURLConnection) url.openConnection();
            //SocketFactory test = SSLCertificateSocketFactory.getDefault(50000);
            SSLSocketFactory test = new PinningSSLSocketFactory();
            urlConnection.setSSLSocketFactory(test);

            InputStream in = urlConnection.getInputStream();
            InputStreamReader isw = new InputStreamReader(in);

            int data = isw.read();
            while (data != -1) {
                char current = (char) data;
                data = isw.read();
                //System.out.print(current);
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
