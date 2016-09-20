package com.datatheorem.android.trustkit;

import android.content.res.XmlResourceParser;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.datatheorem.android.trustkit.config.ConfigurationException;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.pinning.SubjectPublicKeyInfoPin;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;


// TODO(ad): Do not extend HashSet here as it makes the configuration mutable (using HashSet's
// public methods such as add(), etc.) although it should never change once it has been initialized.
// HashSet is the right structure tho so let's just use one as a private attribute instead.
public final class TrustKitConfiguration extends HashSet<PinnedDomainConfiguration> {

    private static final URL DEFAULT_REPORTING_URL;
    static {
        java.net.URL defaultUrl;
        try {
            defaultUrl = new java.net.URL("https://overmind.datatheorem.com/trustkit/report");
        } catch (java.net.MalformedURLException e) {
            throw new IllegalStateException("Bad DEFAULT_REPORTING_URL");
        }
        DEFAULT_REPORTING_URL = defaultUrl;
    }

    /**
     * Return a configuration or null if the specified domain is not pinned.
     * @param serverHostname
     * @return PinnedDomainConfiguration
     */
    @Nullable
    public PinnedDomainConfiguration findConfiguration(@NonNull String serverHostname) {
        for (PinnedDomainConfiguration pinnedDomainConfiguration : this) {
            // TODO(ad): Handle shouldIncludeSubdomains here

            // Check if the configuration for this domain exists and is still valid
            if (serverHostname.equals(pinnedDomainConfiguration.getNotedHostname())) {
                if (pinnedDomainConfiguration.getExpirationDate() == null) {
                    return pinnedDomainConfiguration;
                } else if (pinnedDomainConfiguration.getExpirationDate() != null
                        && pinnedDomainConfiguration.getExpirationDate().compareTo(new Date()) > 0){
                    return pinnedDomainConfiguration;
                } else {
                    return  null;
                }
            }
        }
        return null;
    }

    protected static TrustKitConfiguration fromXmlPolicy(XmlResourceParser parser)
            throws XmlPullParserException, IOException, ParseException {
        TrustKitConfiguration trustKitConfiguration = new TrustKitConfiguration();
        PinnedDomainConfiguration.Builder pinnedDomainConfigBuilder =
                new PinnedDomainConfiguration.Builder();

        // The result of parsing a full domain-config tag
        TrustkitConfigTag trustkitTag = null;
        Set<SubjectPublicKeyInfoPin> publicKeyPins = null;
        DomainTag domainTag = null;

        int eventType = parser.getEventType();
        while (eventType != XmlPullParser.END_DOCUMENT) {
            if (eventType == XmlPullParser.START_TAG) {
                if ("domain-config".equals(parser.getName())) {
                    // New domain configuration - reset all the settings from the previous domain
                    trustkitTag = null;
                    publicKeyPins = null;
                    domainTag = null;
                } else if ("domain".equals(parser.getName())) {
                    domainTag = readDomain(parser);
                } else if ("pin-set".equals(parser.getName())) {
                    publicKeyPins = readPinSet(parser);
                }
                else if ("trustkit-config".equals(parser.getName())) {
                    trustkitTag = readTrustkitConfig(parser);
                }

            } else if (eventType == XmlPullParser.END_TAG) {
                if ("domain-config".equals(parser.getName())) {
                    // End of a domain configuration - store the results
                    pinnedDomainConfigBuilder
                            .pinnedDomainName(domainTag.hostname)
                            .publicKeyHashes(publicKeyPins)
                            .shouldIncludeSubdomains(domainTag.includeSubdomains)
                            .shouldEnforcePinning(trustkitTag.enforcePinning);

                    if (trustkitTag.reportUris != null) {
                        pinnedDomainConfigBuilder.reportUris(trustkitTag.reportUris);
                    }

                    /*
                    if (expirationDate != null) {
                        // TODO(ad): Do not store the config if it is expired
                        pinnedDomainConfigBuilder.expirationDate(expirationDate);
                    }*/

                    // TODO(ad): Add debug overrides

                    trustKitConfiguration.add(pinnedDomainConfigBuilder.build());
                }
            }
            eventType = parser.next();
        }

        if (trustKitConfiguration.size() < 0) {
            throw new ConfigurationException("something wrong with your configuration");
        }

        return trustKitConfiguration;
    }

    private static Set<SubjectPublicKeyInfoPin> readPinSet(XmlPullParser parser) throws IOException,
            XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "pin-set");
        HashSet<SubjectPublicKeyInfoPin> pinSet = new HashSet<>();

        // Look for the expiration attribute
        // TODO(ad): The next line throws an exception when running the tests
                    /*
                    SimpleDateFormat df = new SimpleDateFormat("YYYY-MM-DD", Locale.getDefault());
                    String expirationDateAttr = parser.getAttributeValue(null, "expiration");
                    if (expirationDateAttr != null) {
                        expirationDate =  df.parse(expirationDateAttr);

                    }
                    */

        // Parse until the corresponding close pin-set tag
        int eventType = parser.next();
        while (!((eventType == XmlPullParser.END_TAG) && "pin-set".equals(parser.getName()))) {
            // Look for the next pin tag
            if ((eventType == XmlPullParser.START_TAG) && "pin".equals(parser.getName())) {
                // Found one
                // Sanity check on the digest value
                /*
                String digest = parser.getAttributeValue(null, "digest");
                if (!digest.equals("SHA-256")) {
                    throw new IllegalArgumentException("Unexpected digest value: " + digest);
                }*/

                // Parse until we find the text
                while (eventType != XmlPullParser.TEXT) {
                    eventType = parser.next();
                }
                // Parse the pin value
                pinSet.add(new SubjectPublicKeyInfoPin(parser.getText()));
            }
            parser.next();
        }
        return pinSet;
    }

    private static class TrustkitConfigTag {
        boolean enforcePinning = false;
        Set<URL> reportUris;
    }

    private static TrustkitConfigTag readTrustkitConfig(XmlPullParser parser) throws IOException,
            XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "trustkit-config");

        TrustkitConfigTag result = new TrustkitConfigTag();
        HashSet<URL> reportUris = new HashSet<>();

        // Look for the enforcePinning attribute - default value is false
        String enforcePinning = parser.getAttributeValue(null, "enforcePinning");
        result.enforcePinning = (enforcePinning != null) && enforcePinning.equals("true");

        // Look for the disableDefaultReportUri attribute
        String disableDefaultReportUriStr
                = parser.getAttributeValue(null, "disableDefaultReportUri");
        boolean disableDefaultReportUri = (disableDefaultReportUriStr != null)
                && disableDefaultReportUriStr.equals("true");

        // Parse until the corresponding close trustkit-config tag
        int eventType = parser.next();
        while ((eventType != XmlPullParser.END_TAG) && "trustkit-config".equals(parser.getName())) {
            // Look for the next report-uri tag
            if ((eventType == XmlPullParser.START_TAG) && "report-uri".equals(parser.getName())) {
                // Found one - parse the report-uri value
                reportUris.add(new URL(parser.getText()));
            }
            parser.next();
        }

        // Add the default report URL
        if (!disableDefaultReportUri) {
            reportUris.add(DEFAULT_REPORTING_URL);
        }
        result.reportUris = reportUris;
        return result;
    }

    private static class DomainTag {
        boolean includeSubdomains = false;
        String hostname;
    }

    private static DomainTag readDomain(XmlPullParser parser) throws IOException,
            XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "domain");
        DomainTag result = new DomainTag();

        // Look for the includeSubdomains attribute - default value is false
        String includeSubdomains = parser.getAttributeValue(null, "includeSubdomains");
        result.includeSubdomains = (includeSubdomains != null)
                && includeSubdomains.equals("true");

        // Parse until we find the text
        int eventType = parser.next();
        while (eventType != XmlPullParser.TEXT) {
            eventType = parser.next();
        }
        // Read the hostname
        result.hostname = parser.getText();

        return result;
    }
}

