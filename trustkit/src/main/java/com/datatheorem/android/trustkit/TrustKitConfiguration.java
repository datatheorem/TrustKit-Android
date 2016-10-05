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
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
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

        Set<String> hostnameSet = new HashSet<>();
        for (DomainPinningPolicy domainConfig : domainConfigSet) {
            if (hostnameSet.contains(domainConfig.getHostname())) {
                throw new ConfigurationException("Policy contains the same domain defined twice: "
                        + domainConfig.getHostname());
            }
            hostnameSet.add(domainConfig.getHostname());
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
        DomainPinningPolicy bestMatchPolicy = null;
        for (DomainPinningPolicy domainPolicy : this.domainPolicies) {
            if (domainPolicy.getHostname().equals(serverHostname)) {
                // Found an exact match for this domain
                bestMatchPolicy = domainPolicy;
                break;
            }

            // Look for the best match for pinning policies that include subdomains
            if (domainPolicy.shouldIncludeSubdomains()
                    && isSubdomain(domainPolicy.getHostname(), serverHostname)) {
                if (bestMatchPolicy == null) {
                    bestMatchPolicy = domainPolicy;
                } else if (domainPolicy.getHostname().length() > bestMatchPolicy.getHostname().length()) {
                    bestMatchPolicy = domainPolicy;
                }
            }
        }

        // Ensure that the pinning policy has not expired
        if ((bestMatchPolicy != null) && (bestMatchPolicy.getExpirationDate() != null)) {
            if (bestMatchPolicy.getExpirationDate().compareTo(new Date()) < 0) {
                TrustKitLog.w("Pinning policy for " + serverHostname + " has expired.");
                return null;
            }
        }
        return bestMatchPolicy;
    }

    private static boolean isSubdomain(@NonNull String domain, @NonNull String subdomain) {
        // This returns true for all subdomains, including subdomains of subdomains, similar to how
        // Android N handles includeSubdomains
        return subdomain.endsWith(domain)
                && subdomain.charAt(subdomain.length() - domain.length() - 1) == '.';
    }

    @NonNull
    static TrustKitConfiguration fromXmlPolicy(@NonNull Context context,
                                               @NonNull XmlPullParser parser)
            throws XmlPullParserException, IOException, ParseException, CertificateException {
        // TODO(ad): Handle nested domain config tags
        // https://developer.android.com/training/articles/security-config.html#ConfigInheritance
        // The list of pinned domains retrieved from the policy file
        List<DomainPinningPolicy.Builder> builderList = new ArrayList<>();

        DebugOverridesTag debugOverridesTag = null;

        int eventType = parser.getEventType();
        while (eventType != XmlPullParser.END_DOCUMENT) {
            if (eventType == XmlPullParser.START_TAG) {
                if ("domain-config".equals(parser.getName())) {
                    builderList.addAll(parseConfigEntry(parser, null));
                } else if ("debug-overrides".equals(parser.getName())) {
                    // The Debug-overrides option is global and not tied to a specific domain
                    debugOverridesTag = readDebugOverrides(context, parser);
                }
            }
            eventType = parser.next();
        }

        // Finally, store the result of the parsed policy in our configuration object
        TrustKitConfiguration config;
        HashSet<DomainPinningPolicy> domainConfigSet = new HashSet<>();
        for (DomainPinningPolicy.Builder builder : builderList) {
            domainConfigSet.add(builder.build());
        }

        if (debugOverridesTag != null) {
            config = new TrustKitConfiguration(domainConfigSet, debugOverridesTag.overridePins,
                    debugOverridesTag.debugCaCertificates);
        } else {
            config = new TrustKitConfiguration(domainConfigSet);
        }
        return config;
    }

    // Heavily inspired from
    // https://github.com/android/platform_frameworks_base/blob/master/core/java/android/security/net/config/XmlConfigSource.java
    static private List<DomainPinningPolicy.Builder> parseConfigEntry(
            XmlPullParser parser, DomainPinningPolicy.Builder parentBuilder)
            throws XmlPullParserException, IOException {
        parser.require(XmlPullParser.START_TAG, null, "domain-config");

        DomainPinningPolicy.Builder builder = new DomainPinningPolicy.Builder();
        builder.setParent(parentBuilder);

        List<DomainPinningPolicy.Builder> builderList = new ArrayList<>();
        // Put the current builder as the first one in the list, so the parent always gets built
        // before its children; needed for figuring out the final config when there's inheritance
        builderList.add(builder);

        int eventType = parser.next();
        while (!((eventType == XmlPullParser.END_TAG) && "domain-config".equals(parser.getName()))) {
            if (eventType == XmlPullParser.START_TAG) {
                if ("domain-config".equals(parser.getName())) {
                    // Nested domain configuration tag
                    builderList.addAll(parseConfigEntry(parser, builder));
                } else if ("domain".equals(parser.getName())) {
                    DomainTag domainTag = readDomain(parser);
                    builder.setHostname(domainTag.hostname);
                    builder.setShouldIncludeSubdomains(domainTag.includeSubdomains);
                } else if ("pin-set".equals(parser.getName())) {
                    PinSetTag pinSetTag = readPinSet(parser);
                    builder.setPublicKeyHashes(pinSetTag.pins);
                    builder.setExpirationDate(pinSetTag.expirationDate);
                } else if ("trustkit-config".equals(parser.getName())) {
                    TrustkitConfigTag trustkitTag = readTrustkitConfig(parser);
                    builder.setReportUris(trustkitTag.reportUris);
                    builder.setShouldEnforcePinning(trustkitTag.enforcePinning);
                    builder.setShouldDisableDefaultReportUri(trustkitTag.disableDefaultReportUri);
                }
            }
            eventType = parser.next();
        }
        return builderList;
    }

    private static class PinSetTag {
        Date expirationDate = null;
        Set<String> pins = null;
    }

    @NonNull
    private static PinSetTag readPinSet(@NonNull XmlPullParser parser) throws IOException,
            XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "pin-set");
        PinSetTag pinSetTag = new PinSetTag();
        pinSetTag.pins = new HashSet<>();

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
        int eventType = parser.next();
        while (!((eventType == XmlPullParser.END_TAG) && "pin-set".equals(parser.getName()))) {
            // Look for the next pin tag
            if ((eventType == XmlPullParser.START_TAG) && "pin".equals(parser.getName())) {
                // Found one
                // Sanity check on the digest value
                String digest = parser.getAttributeValue(null, "digest");
                if ((digest == null) || !digest.equals("SHA-256")) {
                    throw new IllegalArgumentException("Unexpected digest value: " + digest);
                }
                // Parse the pin value
                pinSetTag.pins.add(parser.nextText());
            }
            eventType = parser.next();
        }
        return pinSetTag;
    }

    private static class TrustkitConfigTag {
        Boolean enforcePinning = null;
        Boolean disableDefaultReportUri = null;
        Set<String> reportUris;
    }

    @NonNull
    private static TrustkitConfigTag readTrustkitConfig(@NonNull XmlPullParser parser)
            throws IOException, XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "trustkit-config");

        TrustkitConfigTag result = new TrustkitConfigTag();
        Set<String> reportUris = new HashSet<>();

        // Look for the enforcePinning attribute
        String enforcePinning = parser.getAttributeValue(null, "enforcePinning");
        if (enforcePinning != null) {
            result.enforcePinning = Boolean.parseBoolean(enforcePinning);
        }

        // Look for the disableDefaultReportUri attribute
        String disableDefaultReportUri = parser.getAttributeValue(null, "disableDefaultReportUri");
        if (disableDefaultReportUri != null) {
            result.disableDefaultReportUri = Boolean.parseBoolean(disableDefaultReportUri);
        }

        // Parse until the corresponding close trustkit-config tag
        int eventType = parser.next();
        while (!((eventType == XmlPullParser.END_TAG) && "trustkit-config".equals(parser.getName()))) {
            // Look for the next report-uri tag
            if ((eventType == XmlPullParser.START_TAG) && "report-uri".equals(parser.getName())) {
                // Found one - parse the report-uri value
                reportUris.add(parser.nextText());
            }
            eventType = parser.next();
        }

        result.reportUris = reportUris;
        return result;
    }

    private static class DomainTag {
        Boolean includeSubdomains = null;
        String hostname = null;
    }

    @NonNull
    private static DomainTag readDomain(@NonNull XmlPullParser parser) throws IOException,
            XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "domain");
        DomainTag result = new DomainTag();

        // Look for the includeSubdomains attribute
        String includeSubdomains = parser.getAttributeValue(null, "includeSubdomains");
        if (includeSubdomains != null) {
            result.includeSubdomains = Boolean.parseBoolean(includeSubdomains);
        }

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
        while (!((eventType == XmlPullParser.END_TAG) && "trust-anchors".equals(parser.getName()))) {
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
            eventType = parser.next();
        }

        if (lastOverridePinsEncountered != null) {
            result.overridePins = lastOverridePinsEncountered;
        }
        return result;
    }
}
