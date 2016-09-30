package com.datatheorem.android.trustkit;

import android.content.Context;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;

import com.datatheorem.android.trustkit.config.ConfigurationException;
import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;


public final class TrustKitConfiguration {

    @NonNull final private HashSet<DomainPinningPolicy> domainPolicies;

    // For simplicity, this works slightly differently than Android N as we use shouldOverridePins
    // as a global setting instead of a per-<certificates> setting like Android N does
    final private boolean shouldOverridePins;
    @Nullable final private Set<Certificate> debugCaCertificates;

    public boolean shouldOverridePins() {
        // TODO(ad): Let's put the logic here to always return false if we are not in debug mode
        return shouldOverridePins;
    }

    @Nullable
    public Set<Certificate> getDebugCaCertificates() {
        if (!shouldOverridePins) {
            throw new IllegalStateException("Tried to retrieve debug CA certificates when pinning" +
                    "should not be overridden");
        }
        return debugCaCertificates;
    }

    private TrustKitConfiguration(@NonNull HashSet<DomainPinningPolicy> domainConfigSet) {
        this(domainConfigSet, false, null);
    }

    private TrustKitConfiguration(@NonNull HashSet<DomainPinningPolicy> domainConfigSet,
                                  boolean shouldOverridePins,
                                  @Nullable Set<Certificate> DebugCaCerts) {

        if (domainConfigSet.size() < 1) {
            throw new ConfigurationException("Policy contains 0 domains to pin");
        }
        this.domainPolicies = domainConfigSet;
        this.shouldOverridePins = shouldOverridePins;
        this.debugCaCertificates = DebugCaCerts;
    }

    /**
     * Return a configuration or null if the specified domain is not pinned.
     * @param serverHostname
     * @return DomainPinningPolicy
     */
    @Nullable
    public DomainPinningPolicy getConfigForHostname(@NonNull String serverHostname) {
        for (DomainPinningPolicy pinnedDomainConfiguration : this.domainPolicies){
            // TODO(ad): Handle shouldIncludeSubdomains here

            // Check if the configuration for this domain exists and is still valid
            if (serverHostname.equals(pinnedDomainConfiguration.getHostname())) {
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

    @NonNull
    static TrustKitConfiguration fromXmlPolicy(@NonNull Context context,
                                               @NonNull XmlPullParser parser)
            throws XmlPullParserException, IOException, ParseException, CertificateException {
        // The list of pinned domains retrieved from the policy file
        HashSet<DomainPinningPolicy> domainConfigSet = new HashSet<>();

        // Global tag
        DebugOverridesTag debugOverridesTag = new DebugOverridesTag();

        // The result of parsing a domain-config tag
        TrustkitConfigTag trustkitTag = new TrustkitConfigTag();
        PinSetTag pinSetTag = new PinSetTag();
        DomainTag domainTag = new DomainTag();

        int eventType = parser.getEventType();
        while (eventType != XmlPullParser.END_DOCUMENT) {
            if (eventType == XmlPullParser.START_TAG) {
                if ("domain-config".equals(parser.getName())) {
                    // New domain configuration tag - reset all settings from the previous domain
                    trustkitTag = new TrustkitConfigTag();
                    pinSetTag = new PinSetTag();
                    domainTag = new DomainTag();
                } else if ("domain".equals(parser.getName())) {
                    domainTag = readDomain(parser);
                } else if ("pin-set".equals(parser.getName())) {
                    pinSetTag = readPinSet(parser);
                } else if ("trustkit-config".equals(parser.getName())) {
                    trustkitTag = readTrustkitConfig(parser);
                } else if ("debug-overrides".equals(parser.getName())) {
                    // The Debug-overrides option is global and not tied to a specific domain
                    debugOverridesTag = readDebugOverrides(context, parser);
                }

            } else if (eventType == XmlPullParser.END_TAG) {
                if ("domain-config".equals(parser.getName())) {
                    // End of a domain configuration tag - store this domain's settings
                    DomainPinningPolicy domainConfig;
                    domainConfig = new DomainPinningPolicy(domainTag.hostname,
                            domainTag.includeSubdomains, pinSetTag.pins, trustkitTag.enforcePinning,
                            pinSetTag.expirationDate, trustkitTag.reportUris,
                            trustkitTag.disableDefaultReportUri);

                    domainConfigSet.add(domainConfig);
                }
            }
            eventType = parser.next();
        }

        // Finally, store the result of the parsed policy in our configuration object
        TrustKitConfiguration config;
        if (debugOverridesTag != null) {
            config = new TrustKitConfiguration(domainConfigSet, debugOverridesTag.overridePins,
                    debugOverridesTag.debugCaCertificates);
        } else {
            config = new TrustKitConfiguration(domainConfigSet);
        }
        return config;
    }

    private static class PinSetTag {
        Date expirationDate;
        Set<String> pins;
    }

    @NonNull
    private static PinSetTag readPinSet(@NonNull XmlPullParser parser) throws IOException,
            XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "pin-set");
        PinSetTag tag = new PinSetTag();
        tag.pins = new HashSet<>();

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
        Set<String> reportUris;
    }

    @NonNull
    private static TrustkitConfigTag readTrustkitConfig(@NonNull XmlPullParser parser)
            throws IOException, XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "trustkit-config");

        TrustkitConfigTag result = new TrustkitConfigTag();
        Set<String> reportUris = new HashSet<>();

        // Look for the enforcePinning attribute - default value is false
        result.enforcePinning =
                Boolean.parseBoolean(parser.getAttributeValue(null, "enforcePinning"));

        // Look for the disableDefaultReportUri attribute
        result.disableDefaultReportUri
                = Boolean.parseBoolean(parser.getAttributeValue(null, "disableDefaultReportUri"));

        // Parse until the corresponding close trustkit-config tag
        int eventType = parser.next();
        while ((eventType != XmlPullParser.END_TAG) && !"trustkit-config".equals(parser.getName())) {
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

    @NonNull
    private static DomainTag readDomain(@NonNull XmlPullParser parser) throws IOException,
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
        // TODO(ad): The supplied file may contain multiple certificates and also there may be
        // multiple <certificates> tags
        Set<Certificate> debugCaCertificates = null;
    }

    @NonNull
    private static DebugOverridesTag readDebugOverrides(@NonNull Context context,
                                                        @NonNull XmlPullParser parser)
            throws CertificateException, IOException, XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "debug-overrides");
        DebugOverridesTag result = new DebugOverridesTag();
        Boolean lastOverridePinsEncountered = null;

        int eventType = parser.next();
        while ((eventType != XmlPullParser.END_TAG) && "trust-anchors".equals(parser.getName())) {
            parser.nextTag();
            // Look for the next certificates tag
            if ((eventType == XmlPullParser.START_TAG)
                    && "certificates".equals(parser.getName().trim())) {

                // For simplicity, we only support one global overridePins setting, where Android N
                // allows setting overridePins for each debug certificate bundles
                boolean currentOverridePins =
                        Boolean.parseBoolean(parser.getAttributeValue(null, "overridePins"));
                if ((lastOverridePinsEncountered != null)
                        && (lastOverridePinsEncountered != currentOverridePins)) {
                    lastOverridePinsEncountered = false;
                    TrustKitLog.w("Different values for overridePins are set in the policy but " +
                            "TrustKit only supports one value; using overridePins=false for all " +
                            "connections");
                } else {
                    lastOverridePinsEncountered = currentOverridePins;
                }

                // Parse the supplied certificate file
                String caPathFromUser = parser.getAttributeValue(null, "src").trim();

                // The framework expects the certificate to be in the res/raw/ folder of the App
                if (!TextUtils.isEmpty(caPathFromUser) && !caPathFromUser.equals("user")
                        && !caPathFromUser.equals("system") && caPathFromUser.startsWith("@raw")) {

                    InputStream stream =
                            context.getResources().openRawResource(
                                    context.getResources().getIdentifier(
                                            caPathFromUser.split("/")[1], "raw",
                                            context.getPackageName()));

                    result.debugCaCertificates = new HashSet<>();
                    result.debugCaCertificates.add(CertificateFactory.getInstance("X.509")
                            .generateCertificate(stream));

                } else {
                    TrustKitLog.i("No <debug-overrides> certificates found by TrustKit." +
                            " Please check your @raw folder " +
                            "(TrustKit doesn't support system and user installed certificates).");
                }
            }
            parser.next();
        }

        if (lastOverridePinsEncountered != null) {
            result.overridePins = lastOverridePinsEncountered;
        }
        return result;
    }
}
