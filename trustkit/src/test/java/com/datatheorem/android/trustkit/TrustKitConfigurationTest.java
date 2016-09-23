package com.datatheorem.android.trustkit;

import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.pinning.SubjectPublicKeyInfoPin;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.annotation.Config;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.IOException;
import java.io.StringReader;
import java.net.URL;
import java.text.ParseException;
import java.util.HashSet;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

@Config(constants = BuildConfig.class)
@RunWith(RobolectricGradleTestRunner.class)
public class TrustKitConfigurationTest {


    PinnedDomainConfiguration mockPinnedDomainConfiguration;
    String domainName;
    TrustKitConfiguration trustKitConfiguration;

    @Before
    public void setUp() {
        /*
        trustKitConfiguration = new TrustKitConfiguration();
        String pin = "pin-sha256=\"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=\"";
        String pin2 = "pin-sha256=\"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8=\"";
        Set<String> pins = new HashSet<>();
        pins.add(pin);
        pins.add(pin2);
        mockPinnedDomainConfiguration = new PinnedDomainConfiguration.Builder()
                .shouldEnforcePinning(false)
                .shouldDisableDefaultReportUri(true)
                .shouldIncludeSubdomains(false)
                .publicKeyHashes(pins)
                .pinnedDomainName("www.test.com")
                .build();

        domainName = mockPinnedDomainConfiguration.getHostname();
        trustKitConfiguration.add(mockPinnedDomainConfiguration);
        */

    }

    @Test
    public void getByPinnedHostnameTest_HappyCase() {
        //Assert.assertNotNull(trustKitConfiguration.findConfiguration(domainName));
        //Assert.assertEquals(mockPinnedDomainConfiguration, trustKitConfiguration.findConfiguration(domainName));
    }

    @Test
    public void getByPinnedHostnameTest_SadCase() {
        //Assert.assertNull(trustKitConfiguration.findConfiguration("www.toto.com"));
    }

    private XmlPullParser parseXmlString(String xmlString) throws XmlPullParserException {
        XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
        factory.setNamespaceAware(true);
        XmlPullParser xpp = factory.newPullParser();
        xpp.setInput(new StringReader(xmlString));
        return xpp;
    }

    @Test
    public void testXml() throws XmlPullParserException, IOException, ParseException {
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

        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(parseXmlString(xml));
        PinnedDomainConfiguration domainConfig = config.findConfiguration("www.datatheorem.com");

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
