package com.datatheorem.android.trustkit;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.pinning.PublicKeyPin;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.util.HashSet;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class TrustKitConfigurationInstTest {

    private XmlPullParser parseXmlString(String xmlString) throws XmlPullParserException {


        XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
        factory.setNamespaceAware(true);

        XmlPullParser xpp = factory.newPullParser();
        String test = xmlString.replace("\n","").replace("  ","");
        xpp.setInput(new StringReader(test));
        return xpp;
    }

    @Test
    public void testXml() throws XmlPullParserException, IOException, ParseException,
            CertificateException {
        Context context = InstrumentationRegistry.getContext();
        String xml = "" +
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<network-security-config>\n" +
                "    <domain-config>\n" +
                "        <!-- A comment -->\n" +
                "        <domain includeSubdomains=\"true\">www.datatheorem.com</domain>\n" +
                "        <pin-set>\n" +
                "            <!-- Valid pins -->\n" +
                "            <pin digest=\"SHA-256\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>\n" +
                "            <pin digest=\"SHA-256\">grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=</pin>\n" +
                "        </pin-set>\n" +
                "        <trustkit-config enforcePinning=\"true\">\n" +
                "            <report-uri>https://overmind.datatheorem.com/trustkit/report</report-uri>\n" +
                "        </trustkit-config>\n" +
                "    </domain-config>\n" +
                "    <debug-overrides>\n" +
                "        <trust-anchors>\n" +
                "            <certificates overridePins=\"true\" src=\"@raw/cert\"/>\n" +
                "        </trust-anchors>\n" +
                "    </debug-overrides>\n" +
                "</network-security-config>";
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(context,
                parseXmlString(xml));
        //The test for the certificate need to be in the androidTest instead of the test folder
        //because of the res/raw/ folder.
        int certResId =
                context.getResources().getIdentifier("cert", "raw", context.getPackageName());
        InputStream certStream = context.getResources().openRawResource(certResId);
        Certificate expectedCert =
                CertificateFactory.getInstance("X.509").generateCertificate(certStream);
        assertTrue(config.shouldOverridePins());
        assertEquals(expectedCert, config.getDebugCaCertificates().get(0));
    }
}
