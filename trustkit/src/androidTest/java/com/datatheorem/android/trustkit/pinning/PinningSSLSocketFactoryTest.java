package com.datatheorem.android.trustkit.pinning;



import android.support.test.InstrumentationRegistry;
import android.support.test.filters.SmallTest;
import android.support.test.runner.AndroidJUnit4;

import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.TrustKitConfiguration;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;

import org.junit.Test;
import org.junit.runner.RunWith;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;


@RunWith(AndroidJUnit4.class)
@SmallTest
public class PinningSSLSocketFactoryTest {

    @Test
    public void someConnection() {
        String pin = "rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=";
        String pin2 = "0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8=";
        Set<String> pins = new HashSet<>();
        pins.add(pin);
        pins.add(pin2);
        // Initialize TrustKit
        TrustKitConfiguration trustKitConfig = new TrustKitConfiguration();
        PinnedDomainConfiguration datatheoremConfig = new PinnedDomainConfiguration.Builder()
                .pinnedDomainName("www.datatheorem.com")
                .publicKeyHashes(pins)
                .enforcePinning(false)
                .build();
        trustKitConfig.add(datatheoremConfig);
        TrustKit.init(InstrumentationRegistry.getContext(), trustKitConfig);


        URL url;
        HttpsURLConnection urlConnection = null;
        try {
            url = new URL("https://wrong.host.badssl.com/");
            url = new URL("https://204.11.59.148/");
            url = new URL("https://www.datatheorem.com");
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
