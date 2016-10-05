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
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;
import static junit.framework.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class TrustKitConfigurationTest {

    private XmlPullParser parseXmlString(String xmlString) throws XmlPullParserException {


        XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
        factory.setNamespaceAware(true);

        XmlPullParser xpp = factory.newPullParser();
        String test = xmlString.replace("\n","").replace("  ","");
        xpp.setInput(new StringReader(test));
        return xpp;
    }

    @Test
    public void testDefaultValues() throws XmlPullParserException, IOException, ParseException,
            CertificateException {
        Context context = InstrumentationRegistry.getContext();
        String xml = "" +
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<network-security-config>\n" +
                "    <domain-config>\n" +
                "        <domain>www.datatheorem.com</domain>\n" +
                "        <pin-set>\n" +
                "            <pin digest=\"SHA-256\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>\n" +
                "            <pin digest=\"SHA-256\">grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=</pin>\n" +
                "        </pin-set>\n" +
                "        <trustkit-config>\n" +
                "            <report-uri>https://some.reportdomain.com/</report-uri>\n" +
                "        </trustkit-config>\n" +
                "    </domain-config>\n" +
                "</network-security-config>";
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(context,
                parseXmlString(xml));

        // Validate the domain's configuration
        DomainPinningPolicy domainConfig = config.getConfigForHostname("www.datatheorem.com");

        assertEquals("www.datatheorem.com", domainConfig.getHostname());
        // Validate default values
        assertFalse(domainConfig.shouldIncludeSubdomains());
        assertFalse(domainConfig.shouldEnforcePinning());

        HashSet<URL> expectedUri = new HashSet<URL>() {{
            add(new java.net.URL("https://some.reportdomain.com/"));
            // The default report URI should be there too
            add(new java.net.URL("https://overmind.datatheorem.com/trustkit/report"));
        }};
        assertEquals(expectedUri, domainConfig.getReportUris());

        HashSet<PublicKeyPin> expectedPins = new HashSet<PublicKeyPin>() {{
            add(new PublicKeyPin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
            add(new PublicKeyPin("grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME="));
        }};
        assertEquals(expectedPins, domainConfig.getPublicKeyHashes());
    }

    @Test
    public void testIncludeSubdomainsAndNoTrustkitTag() throws XmlPullParserException, IOException,
            ParseException, CertificateException {
        Context context = InstrumentationRegistry.getContext();
        String xml = "" +
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<network-security-config>\n" +
                "    <domain-config>\n" +
                "        <domain includeSubdomains=\"true\">datatheorem.com</domain>\n" +
                "        <pin-set>\n" +
                "            <pin digest=\"SHA-256\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>\n" +
                "            <pin digest=\"SHA-256\">grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=</pin>\n" +
                "        </pin-set>\n" +
                "    </domain-config>\n" +
                "</network-security-config>";
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(context,
                parseXmlString(xml));

        // Ensure a valid subdomain gets the policy
        DomainPinningPolicy domainConfig = config.getConfigForHostname("subdomain.datatheorem.com");
        assertNotNull(domainConfig);
        assertEquals("datatheorem.com", domainConfig.getHostname());

        // Ensure a domain that is a subdomain of a subdomain gets the policy
        domainConfig = config.getConfigForHostname("sub.subdomain.datatheorem.com");
        assertNotNull(domainConfig);

        // Ensure a domain that is not a subdomain does not get the policy
        domainConfig = config.getConfigForHostname("subdomain.datatheorem.fr");
        assertNull(domainConfig);
    }

    @Test
    public void testEnforcePinning() throws XmlPullParserException, IOException,
            ParseException, CertificateException {
        Context context = InstrumentationRegistry.getContext();
        String xml = "" +
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<network-security-config>\n" +
                "    <domain-config>\n" +
                "        <domain>www.datatheorem.com</domain>\n" +
                "        <pin-set>\n" +
                "            <pin digest=\"SHA-256\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>\n" +
                "            <pin digest=\"SHA-256\">grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=</pin>\n" +
                "        </pin-set>\n" +
                "        <trustkit-config enforcePinning=\"true\">\n" +
                "        </trustkit-config>\n" +
                "    </domain-config>\n" +
                "</network-security-config>";
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(context,
                parseXmlString(xml));

        DomainPinningPolicy domainConfig = config.getConfigForHostname("www.datatheorem.com");
        assertTrue(domainConfig.shouldEnforcePinning());
    }

    @Test
    public void testDisableDefaultReportUri() throws XmlPullParserException, IOException,
            ParseException, CertificateException {
        Context context = InstrumentationRegistry.getContext();
        String xml = "" +
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<network-security-config>\n" +
                "    <domain-config>\n" +
                "        <domain>www.datatheorem.com</domain>\n" +
                "        <pin-set>\n" +
                "            <pin digest=\"SHA-256\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>\n" +
                "            <pin digest=\"SHA-256\">grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=</pin>\n" +
                "        </pin-set>\n" +
                "        <trustkit-config disableDefaultReportUri=\"true\">\n" +
                "        </trustkit-config>\n" +
                "    </domain-config>\n" +
                "</network-security-config>";
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(context,
                parseXmlString(xml));

        // Ensure the list of report URIs is empty
        DomainPinningPolicy domainConfig = config.getConfigForHostname("www.datatheorem.com");
        assertEquals(new HashSet<>(), domainConfig.getReportUris());
    }

    @Test
    public void testDebugOverrides() throws XmlPullParserException, IOException,
            ParseException, CertificateException {
        Context context = InstrumentationRegistry.getContext();
        String xml = "" +
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<network-security-config>\n" +
                "    <domain-config>\n" +
                "        <domain>www.datatheorem.com</domain>\n" +
                "        <pin-set>\n" +
                "            <pin digest=\"SHA-256\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>\n" +
                "            <pin digest=\"SHA-256\">grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=</pin>\n" +
                "        </pin-set>\n" +
                "    </domain-config>\n" +
                "    <debug-overrides>\n" +
                "        <trust-anchors>\n" +
                "            <certificates overridePins=\"true\" src=\"@raw/cert\"/>\n" +
                "        </trust-anchors>\n" +
                "    </debug-overrides>\n" +
                "</network-security-config>";
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(context,
                parseXmlString(xml));

        // Validate the debug overrides configuration
        int certResId =
                context.getResources().getIdentifier("cert", "raw", context.getPackageName());
        InputStream certStream = context.getResources().openRawResource(certResId);
        Certificate expectedCert =
                CertificateFactory.getInstance("X.509").generateCertificate(certStream);
        assertTrue(config.shouldOverridePins());
        // TODO(ad): Handle multiple certificates
        assertTrue(config.getDebugCaCertificates().contains(expectedCert));
    }

    @Test
    public void testNestedDomainConfig() throws XmlPullParserException, IOException,
            ParseException, CertificateException {
        Context context = InstrumentationRegistry.getContext();
        String xml = "" +
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<network-security-config>\n" +
                "    <domain-config>\n" +
                "        <domain includeSubdomains=\"true\">datatheorem.com</domain>\n" +
                "        <pin-set>\n" +
                "            <pin digest=\"SHA-256\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>\n" +
                "            <pin digest=\"SHA-256\">grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=</pin>\n" +
                "        </pin-set>\n" +
                "        <trustkit-config disableDefaultReportUri=\"true\">\n" +
                "        </trustkit-config>\n" +
                // A more specific domain-config is nested here
                "        <domain-config>\n" +
                "            <domain>nested.datatheorem.com</domain>\n" +
                "            <pin-set>\n" +
                "                <pin digest=\"SHA-256\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>\n" +
                "                <pin digest=\"SHA-256\">grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=</pin>\n" +
                "            </pin-set>\n" +
                "            <trustkit-config>\n" +
                "                <report-uri>https://some.reportdomain.com/</report-uri>\n" +
                "            </trustkit-config>\n" +
                "        </domain-config>\n" +
                // An empty domain-config is nested here
                "        <domain-config>\n" +
                "            <domain>other.datatheorem.com</domain>\n" +
                "        </domain-config>\n" +
                "    </domain-config>\n" +
                "</network-security-config>";
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(context,
                parseXmlString(xml));

        // Ensure the list of report URIs is empty
        DomainPinningPolicy domainConfig = config.getConfigForHostname("www.datatheorem.com");
        assertEquals(new HashSet<>(), domainConfig.getReportUris());
    }
}
