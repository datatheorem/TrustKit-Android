package com.datatheorem.android.trustkit.config;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;
import static junit.framework.Assert.assertTrue;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

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
    public void testBadHostnameValidation() throws XmlPullParserException, IOException, CertificateException {
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
                "</network-security-config>";
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(context,
                parseXmlString(xml));

        // Ensure that something that isn't a domain (such as a URL) gets rejected
        boolean wasBadDomainRejected = false;
        try {
            config.getPolicyForHostname("https://www.datatheorem.com");
        } catch (IllegalArgumentException e) {
            wasBadDomainRejected = true;
        }
        assertTrue(wasBadDomainRejected);
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
        DomainPinningPolicy domainConfig = config.getPolicyForHostname("www.datatheorem.com");

        assertNotNull(domainConfig);
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
        assertEquals(expectedPins, domainConfig.getPublicKeyPins());
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
        DomainPinningPolicy domainConfig = config.getPolicyForHostname("subdomain.datatheorem.com");
        assertNotNull(domainConfig);
        assertEquals("datatheorem.com", domainConfig.getHostname());

        // Ensure a domain that is a subdomain of a subdomain gets the policy
        domainConfig = config.getPolicyForHostname("sub.subdomain.datatheorem.com");
        assertNotNull(domainConfig);

        // Ensure a domain that is not a subdomain does not get the policy
        domainConfig = config.getPolicyForHostname("subdomain.datatheorem.fr");
        assertNull(domainConfig);

        // REVIEW(bj): What does the report URI HashSet look like in this case?
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

        DomainPinningPolicy domainConfig = config.getPolicyForHostname("www.datatheorem.com");
        assertNotNull(domainConfig);
        assertTrue(domainConfig.shouldEnforcePinning());
    }


    @Test
    public void testExpirationDate() throws XmlPullParserException, IOException,
            ParseException, CertificateException {
        Context context = InstrumentationRegistry.getContext();
        String xml = "" +
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<network-security-config>\n" +
                "    <domain-config>\n" +
                "        <domain>www.datatheorem.com</domain>\n" +
                "        <pin-set expiration=\"2018-01-01\">\n" +
                "            <pin digest=\"SHA-256\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>\n" +
                "            <pin digest=\"SHA-256\">grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=</pin>\n" +
                "        </pin-set>\n" +
                "    </domain-config>\n" +
                "</network-security-config>";
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(context,
                parseXmlString(xml));
        SimpleDateFormat parser = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
        Date expectedDate = parser.parse("2018-01-01");

        DomainPinningPolicy serverConfig = config.getPolicyForHostname("www.datatheorem.com");
        assertNotNull(serverConfig);
        assertEquals(serverConfig.getExpirationDate(), expectedDate);
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
        DomainPinningPolicy domainConfig = config.getPolicyForHostname("www.datatheorem.com");
        assertNotNull(domainConfig);
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
                "            <certificates overridePins=\"true\" src=\"@raw/good\"/>\n" +
                "            <certificates overridePins=\"true\" src=\"@raw/cacertorg\"/>\n" +
                // We ignore src=sytem or user
                "            <certificates overridePins=\"true\" src=\"system\"/>\n" +
                "        </trust-anchors>\n" +
                "    </debug-overrides>\n" +
                "</network-security-config>";
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(context,
                parseXmlString(xml));

        // Validate the debug overrides configuration
        int goodCertResId =
                context.getResources().getIdentifier("good", "raw", context.getPackageName());
        InputStream goodCertStream = context.getResources().openRawResource(goodCertResId);
        final Certificate goodCert =
                CertificateFactory.getInstance("X.509").generateCertificate(goodCertStream);
        assertTrue(config.shouldOverridePins());
        int caCertResId =
                context.getResources().getIdentifier("cacertorg", "raw", context.getPackageName());
        InputStream caCertStream = context.getResources().openRawResource(caCertResId);
        final Certificate caCert =
                CertificateFactory.getInstance("X.509").generateCertificate(caCertStream);
        assertTrue(config.shouldOverridePins());

        HashSet expectedCertificates = new HashSet<Certificate>() {{
            add(goodCert);
            add(caCert);
        }};
        assertEquals(expectedCertificates, config.getDebugCaCertificates());
    }

    @Test
    public void testNestedDomainConfig() throws XmlPullParserException, IOException,
            ParseException, CertificateException {
        Context context = InstrumentationRegistry.getContext();
        String xml = "" +
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<network-security-config>\n" +
                "    <domain-config>\n" +
                // A more specific domain-config for a subdomain is nested here
                "        <domain-config enforcePinning=\"true\" >\n" +
                "            <domain>other.datatheorem.com</domain>\n" +
                "            <pin-set>\n" +
                "                <pin digest=\"SHA-256\">CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=</pin>\n" +
                "                <pin digest=\"SHA-256\">DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=</pin>\n" +
                "            </pin-set>\n" +
                "            <trustkit-config disableDefaultReportUri=\"false\">\n" +
                "            </trustkit-config>\n" +
                "        </domain-config>\n" +
                "        <domain includeSubdomains=\"true\">datatheorem.com</domain>\n" +
                "        <pin-set>\n" +
                "            <pin digest=\"SHA-256\">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>\n" +
                "            <pin digest=\"SHA-256\">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>\n" +
                "        </pin-set>\n" +
                "        <trustkit-config disableDefaultReportUri=\"true\">\n" +
                "        </trustkit-config>\n" +
                // A more specific domain-config for an unrelated domain is nested here
                "        <domain-config enforcePinning=\"true\">\n" +
                "            <domain>unrelated.domain.com</domain>\n" +
                "            <trustkit-config>\n" +
                "                <report-uri>https://some.reportdomain.com/</report-uri>\n" +
                "            </trustkit-config>\n" +
                "        </domain-config>\n" +
                "    </domain-config>\n" +
                "</network-security-config>";
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(context,
                parseXmlString(xml));

        // Validate the configuration of the parent domain-config
        DomainPinningPolicy domainConfig = config.getPolicyForHostname("datatheorem.com");
        assertNotNull(domainConfig);
        assertEquals(new HashSet<>(), domainConfig.getReportUris());

        HashSet<PublicKeyPin> expectedPins = new HashSet<PublicKeyPin>() {{
            add(new PublicKeyPin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
            add(new PublicKeyPin("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="));
        }};
        assertEquals(expectedPins, domainConfig.getPublicKeyPins());

        // Validate the configuration of the parent domain-config for a subdomain
        domainConfig = config.getPolicyForHostname("subdomain.datatheorem.com");
        assertNotNull(domainConfig);
        assertEquals(new HashSet<>(), domainConfig.getReportUris());
        assertEquals(expectedPins, domainConfig.getPublicKeyPins());

        // Validate the configuration of a nested domain-config for a subdomain
        domainConfig = config.getPolicyForHostname("other.datatheorem.com");

        HashSet<PublicKeyPin> expectedOtherPins = new HashSet<PublicKeyPin>() {{
            add(new PublicKeyPin("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="));
            add(new PublicKeyPin("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="));
        }};
        assertNotNull(domainConfig);
        assertEquals(expectedOtherPins, domainConfig.getPublicKeyPins());

        HashSet<URL> expectedUri = new HashSet<URL>() {{
            // The default report URI should be there
            add(new java.net.URL("https://overmind.datatheorem.com/trustkit/report"));
        }};
        assertEquals(expectedUri, domainConfig.getReportUris());

        // Validate the configuration of a nested domain-config for an unrelated domain
        domainConfig = config.getPolicyForHostname("unrelated.domain.com");
        assertNotNull(domainConfig);
        assertEquals(expectedPins, domainConfig.getPublicKeyPins());

        HashSet<URL> expectedUnrelatedUri = new HashSet<URL>() {{
            // The default report URI should be there
            add(new java.net.URL("https://some.reportdomain.com/"));
        }};
        assertEquals(expectedUnrelatedUri, domainConfig.getReportUris());
    }

    @Test
    public void testIgnoreDomainWithNoPins(
    ) throws XmlPullParserException, IOException, CertificateException {
        Context context = InstrumentationRegistry.getContext();
        // Given a valid network security config
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

                // That has a domain-config entry with no pin-set
                "    <domain-config cleartextTrafficPermitted=\"true\">\n" +
                "        <domain includeSubdomains=\"false\">localhost</domain>\n" +
                "        <domain includeSubdomains=\"false\">10.0.2.2</domain>\n" +
                "    </domain-config>\n" +
                "</network-security-config>";

        // When parsing the config
        TrustKitConfiguration config = TrustKitConfiguration.fromXmlPolicy(
                context, parseXmlString(xml)
        );

        // It succeeds
        DomainPinningPolicy datathDomainConfig = config.getPolicyForHostname("www.datatheorem.com");
        assertNotNull(datathDomainConfig);

        // And the domain-config entry with no pin-set was ignored
        DomainPinningPolicy noPinSetDomainConfig = config.getPolicyForHostname("localhost");
        assertNull(noPinSetDomainConfig);
    }
}
