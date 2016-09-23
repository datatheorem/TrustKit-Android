package com.datatheorem.android.trustkit;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.datatheorem.android.trustkit.config.ConfigurationException;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;



public final class TrustKitConfiguration{

    private HashSet<PinnedDomainConfiguration> pinnedDomainConfigurations;
    private boolean shouldOverridePins = false;
    private Certificate caIfDebug = null;

    private void setShouldOverridePins(boolean overridePins) {
        this.shouldOverridePins = overridePins;
    }

    public boolean shouldOverridePins() {
        // TODO(ad): Let's put the logic here to always return false if we are not in debug mode
        return shouldOverridePins;
    }

    private void setCaFilePathIfDebug(Certificate caIfDebug) {
        this.caIfDebug = caIfDebug;
    }

    public Certificate getCaFilePathIfDebug() {
        return caIfDebug;
    }

    public HashSet<PinnedDomainConfiguration> getPinnedDomainConfigurations() {
        return pinnedDomainConfigurations;
    }

    public TrustKitConfiguration() {
        this.pinnedDomainConfigurations = new HashSet<>();
    }

    public TrustKitConfiguration(HashSet<PinnedDomainConfiguration> pinnedDomainConfigurations) {
        this.pinnedDomainConfigurations = pinnedDomainConfigurations;
    }

    /**
     * Return a configuration or null if the specified domain is not pinned.
     * @param serverHostname
     * @return PinnedDomainConfiguration
     */
    @Nullable
    public PinnedDomainConfiguration findConfiguration(@NonNull String serverHostname) {
        for (PinnedDomainConfiguration pinnedDomainConfiguration : this.pinnedDomainConfigurations){
            // TODO(ad): Handle shouldIncludeSubdomains here

            // Check if the configuration for this domain exists and is still valid
            if (serverHostname.equals(pinnedDomainConfiguration.getNotedHostname())) {
                if (pinnedDomainConfiguration.getExpirationDate() == null) {
                    return pinnedDomainConfiguration;
                } else if (pinnedDomainConfiguration.getExpirationDate() != null
                        && pinnedDomainConfiguration.getExpirationDate().compareTo(new Date()) > 0){
                    return pinnedDomainConfiguration;
                } else {
                    // TODO(ad): Log the fact that the configuration expired
                    return  null;
                }
            }
        }
        return null;
    }


    static TrustKitConfiguration fromXmlPolicy(Context context, XmlPullParser parser)
            throws XmlPullParserException, IOException, ParseException, CertificateException {

        TrustKitConfiguration trustKitConfiguration = new TrustKitConfiguration();
        PinnedDomainConfiguration.Builder pinnedDomainConfigBuilder =
                new PinnedDomainConfiguration.Builder();


        // The result of parsing a full domain-config tag
        TrustkitConfigTag trustkitTag = null;
        PinSetTag pinSetTag = null;
        DomainTag domainTag = null;
        DebugOverridesTag debugOverridesTag = null;


        int eventType = parser.getEventType();
        while (eventType != XmlPullParser.END_DOCUMENT) {
            if (eventType == XmlPullParser.START_TAG) {
                if ("domain-config".equals(parser.getName())) {
                    // New domain configuration - reset all the settings from the previous domain
                    trustkitTag = null;
                    pinSetTag = null;
                    domainTag = null;
                    debugOverridesTag = null;
                } else if ("domain".equals(parser.getName())) {
                    domainTag = readDomain(parser);
                } else if ("pin-set".equals(parser.getName())) {
                    pinSetTag = readPinSet(parser);
                } else if ("trustkit-config".equals(parser.getName())) {
                    trustkitTag = readTrustkitConfig(parser);
                } else if ("debug-overrides".equals(parser.getName())) {
                    // The Debug-overrides option is global and not tied to a specific domain
                    debugOverridesTag = readDebugOverrides(parser, context);
                    trustKitConfiguration.setShouldOverridePins(debugOverridesTag.overridePins);
                    if (debugOverridesTag.caFileIfDebug != null) {
                        trustKitConfiguration.setCaFilePathIfDebug(debugOverridesTag.caFileIfDebug);
                    }
                }

            } else if (eventType == XmlPullParser.END_TAG) {
                if ("domain-config".equals(parser.getName())) {
                    // End of a domain configuration - store the results
                    pinnedDomainConfigBuilder
                            .pinnedDomainName(domainTag.hostname)
                            .publicKeyHashes(pinSetTag.pins)
                            .shouldIncludeSubdomains(domainTag.includeSubdomains)
                            .shouldEnforcePinning(trustkitTag.enforcePinning)
                            .shouldDisableDefaultReportUri(trustkitTag.disableDefaultReportUri);

                    if (trustkitTag.reportUris != null) {
                        pinnedDomainConfigBuilder.reportUris(trustkitTag.reportUris);
                    }

                    if (pinSetTag.expirationDate != null) {
                        pinnedDomainConfigBuilder.expirationDate(pinSetTag.expirationDate);
                    }

                    trustKitConfiguration.pinnedDomainConfigurations
                            .add(pinnedDomainConfigBuilder.build());
                }
            }
            eventType = parser.next();
        }

        if (trustKitConfiguration.pinnedDomainConfigurations.size() < 0) {
            throw new ConfigurationException("something wrong with your configuration");
        }

        return trustKitConfiguration;
    }

    private static class PinSetTag {
        Date expirationDate;
        List<String> pins;
    }

    private static PinSetTag readPinSet(XmlPullParser parser) throws IOException,
            XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "pin-set");
        PinSetTag tag = new PinSetTag();
        tag.pins = new ArrayList<>();

        // Look for the expiration attribute
        // TODO(ad): The next line throws an exception when running the tests
                    /*
                    SimpleDateFormat df = new SimpleDateFormat("YYYY-MM-DD", Locale.getDefault());
                    String expirationDateAttr = parser.getAttributeValue(null, "expiration");
                    if (expirationDateAttr != null) {
                        pinSetTag.expirationDate =  df.parse(expirationDateAttr);

                    }
                    */

        // Parse until the corresponding close pin-set tag
        int eventType = parser.nextTag();
        while ((eventType != XmlPullParser.END_TAG) && !"pin-set".equals(parser.getName())) {
            // Look for the next pin tag
            if ((eventType == XmlPullParser.START_TAG) && "pin".equals(parser.getName())) {
                // Found one
                // Sanity check on the digest value
                String digest = parser.getAttributeValue(null, "digest");
                if (!digest.equals("SHA-256")) {
                    throw new IllegalArgumentException("Unexpected digest value: " + digest);
                }
                // Parse the pin value
                tag.pins.add(parser.nextText());
            }
            parser.nextTag();
        }
        return tag;
    }

    private static class TrustkitConfigTag {
        boolean enforcePinning = false;
        boolean disableDefaultReportUri = false;
        List<String> reportUris;
    }

    private static TrustkitConfigTag readTrustkitConfig(XmlPullParser parser) throws IOException,
            XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "trustkit-config");

        TrustkitConfigTag result = new TrustkitConfigTag();
        ArrayList<String> reportUris = new ArrayList<>();

        // Look for the enforcePinning attribute - default value is false
        result.enforcePinning =
                Boolean.parseBoolean(parser.getAttributeValue(null, "enforcePinning"));


        // Look for the disableDefaultReportUri attribute
        result.disableDefaultReportUri
                = Boolean.parseBoolean(parser.getAttributeValue(null, "disableDefaultReportUri"));


        // Parse until the corresponding close trustkit-config tag
        int eventType = parser.next();
        while ((eventType != XmlPullParser.END_TAG) && "trustkit-config".equals(parser.getName())) {
            // Look for the next report-uri tag
            if ((eventType == XmlPullParser.START_TAG) && "report-uri".equals(parser.getName())) {
                // Found one - parse the report-uri value
                reportUris.add(parser.nextText());
            }
            parser.next();
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

        result.includeSubdomains =
                Boolean.parseBoolean(parser.getAttributeValue(null, "includeSubdomains"));

        // Parse the domain text
        result.hostname = parser.nextText();
        return result;
    }

    private static class DebugOverridesTag {
        boolean overridePins = false;
        // TODO(ad): The supplied file may contain multiple certificates
        Certificate caFileIfDebug = null;
    }

    private static DebugOverridesTag readDebugOverrides(XmlPullParser parser, Context context)
            throws CertificateException, IOException, XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "debug-overrides");
        DebugOverridesTag result = new DebugOverridesTag();

        result.overridePins = Boolean.parseBoolean(parser.getAttributeValue(null, "overridePins"));

        String caPathFromUser = parser.getAttributeValue(null, "src");
        // TODO(ad): Log a warning when the src is not @raw to let developers know that TrustKit
        // will not process the user and system options
        //The framework expects the certificate to be in the res/raw/ folder of
        //the application. It could be possible to put it in other folders but
        //I haven't seen any other examples in the android source code for now.
        //So I've decided to
        if (!caPathFromUser.equals("user") && !caPathFromUser.equals("system")
                && !caPathFromUser.equals("") && caPathFromUser.startsWith("@raw")) {

            InputStream stream =
                    context.getResources().openRawResource(
                            context.getResources().getIdentifier(
                                    caPathFromUser.split("/")[1], "raw",
                                    context.getPackageName()));

            result.caFileIfDebug =
                    CertificateFactory.getInstance("X.509").generateCertificate(stream);
        }

        return result;
    }

}

