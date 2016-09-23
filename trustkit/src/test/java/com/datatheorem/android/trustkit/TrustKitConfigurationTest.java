package com.datatheorem.android.trustkit;

import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.pinning.SubjectPublicKeyInfoPin;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.IOException;
import java.io.StringReader;
import java.net.URL;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.HashSet;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

@Config(constants = BuildConfig.class)
@RunWith(RobolectricGradleTestRunner.class)
public class TrustKitConfigurationTest {

    private XmlPullParser parseXmlString(String xmlString) throws XmlPullParserException {
        XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
        factory.setNamespaceAware(true);
        XmlPullParser xpp = factory.newPullParser();
        xpp.setInput(new StringReader(xmlString));
        return xpp;
    }

    @Test
    public void testXml() throws XmlPullParserException, IOException, ParseException,
            CertificateException {
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
                "        </trustkit-config>\n" +
                "    </domain-config>\n" +
                "</network-security-config>";

        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(
                RuntimeEnvironment.application, parseXmlString(xml));
        DomainPinningPolicy domainConfig = config.findConfiguration("www.datatheorem.com");

        assertEquals(domainConfig.getHostname(), "www.datatheorem.com");
        assertTrue(domainConfig.shouldIncludeSubdomains());
        assertTrue(domainConfig.shouldEnforcePinning());

        HashSet<URL> expectedUri = new HashSet<>();
        expectedUri.add(new java.net.URL("https://overmind.datatheorem.com/trustkit/report"));
        assertEquals(domainConfig.getReportUris(), expectedUri);

        HashSet<SubjectPublicKeyInfoPin> expectedPins = new HashSet<>();
        expectedPins.add(new SubjectPublicKeyInfoPin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        expectedPins.add(new SubjectPublicKeyInfoPin("grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME="));
        assertEquals(domainConfig.getPublicKeyHashes(), expectedPins);
    }
}
