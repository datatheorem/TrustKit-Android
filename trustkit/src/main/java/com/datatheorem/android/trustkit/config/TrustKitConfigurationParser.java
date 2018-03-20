package com.datatheorem.android.trustkit.config;


import android.content.Context;
import android.support.annotation.NonNull;
import android.text.TextUtils;

import android.util.Log;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;


class TrustKitConfigurationParser {

    /**
     * Parse an XML TrustKit / Network Security policy and return the corresponding
     * {@link TrustKitConfiguration}.
     */
    @NonNull
    public static TrustKitConfiguration fromXmlPolicy(@NonNull Context context,
                                                      @NonNull XmlPullParser parser)
            throws XmlPullParserException, IOException, CertificateException {
        // Handle nested domain config tags
        // https://developer.android.com/training/articles/security-config.html#ConfigInheritance
        List<DomainPinningPolicy.Builder> builderList = new ArrayList<>();

        DebugOverridesTag debugOverridesTag = null;

        int eventType = parser.getEventType();
        while (eventType != XmlPullParser.END_DOCUMENT) {
            if (eventType == XmlPullParser.START_TAG) {
                if ("domain-config".equals(parser.getName())) {
                    builderList.addAll(readDomainConfig(parser, null));
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
    private static List<DomainPinningPolicy.Builder> readDomainConfig(
            XmlPullParser parser, DomainPinningPolicy.Builder parentBuilder)
            throws XmlPullParserException, IOException {
        parser.require(XmlPullParser.START_TAG, null, "domain-config");

        DomainPinningPolicy.Builder builder = new DomainPinningPolicy.Builder()
                .setParent(parentBuilder);

        List<DomainPinningPolicy.Builder> builderList = new ArrayList<>();
        // Put the current builder as the first one in the list, so the parent always gets built
        // before its children; needed for figuring out the final config when there's inheritance
        builderList.add(builder);

        int eventType = parser.next();
        while (!((eventType == XmlPullParser.END_TAG) && "domain-config".equals(parser.getName()))) {
            if (eventType == XmlPullParser.START_TAG) {
                if ("domain-config".equals(parser.getName())) {
                    // Nested domain configuration tag
                    builderList.addAll(readDomainConfig(parser, builder));
                } else if ("domain".equals(parser.getName())) {
                    DomainTag domainTag = readDomain(parser);
                    builder.setHostname(domainTag.hostname)
                            .setShouldIncludeSubdomains(domainTag.includeSubdomains);
                } else if ("pin-set".equals(parser.getName())) {
                    PinSetTag pinSetTag = readPinSet(parser);
                    builder.setPublicKeyHashes(pinSetTag.pins)
                            .setExpirationDate(pinSetTag.expirationDate);
                } else if ("trustkit-config".equals(parser.getName())) {
                    TrustkitConfigTag trustkitTag = readTrustkitConfig(parser);
                    builder.setReportUris(trustkitTag.reportUris)
                            .setShouldEnforcePinning(trustkitTag.enforcePinning)
                            .setShouldDisableDefaultReportUri(trustkitTag.disableDefaultReportUri);
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
        // Taken from https://github.com/android/platform_frameworks_base/blob/master/core/java/android/security/net/config/XmlConfigSource.java
        String expirationDate = parser.getAttributeValue(null, "expiration");
        if (expirationDate != null) {
            try {
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
                sdf.setLenient(false);
                Date date = sdf.parse(expirationDate);
                if (date == null) {
                    throw new ConfigurationException("Invalid expiration date in pin-set");
                }
                pinSetTag.expirationDate = date;
            } catch (ParseException e) {
                throw new ConfigurationException("Invalid expiration date in pin-set");
            }
        }

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
        Boolean enforcePinning = false;
        Boolean disableDefaultReportUri;
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
        Set<Certificate> debugCaCertificates = null;
    }

    @NonNull
    private static DebugOverridesTag readDebugOverrides(@NonNull Context context,
                                                        @NonNull XmlPullParser parser)
            throws CertificateException, IOException, XmlPullParserException {
        parser.require(XmlPullParser.START_TAG, null, "debug-overrides");
        DebugOverridesTag result = new DebugOverridesTag();
        Boolean lastOverridePinsEncountered = null;
        Set<Certificate> debugCaCertificates = new HashSet<>();

        int eventType = parser.next();
        while (!((eventType == XmlPullParser.END_TAG) && "trust-anchors".equals(parser.getName()))) {
            // Look for the next certificates tag
            if ((eventType == XmlPullParser.START_TAG) && "certificates".equals(parser.getName())) {
                // For simplicity, we only support one global overridePins setting, where Android N
                // allows setting overridePins for each debug certificate bundles
                boolean currentOverridePins =
                        Boolean.parseBoolean(parser.getAttributeValue(null, "overridePins"));
                if ((lastOverridePinsEncountered != null)
                        && (lastOverridePinsEncountered != currentOverridePins)) {
                    lastOverridePinsEncountered = false;
                    TrustKitLog.w("Warning: different values for overridePins are set in the " +
                            "policy but TrustKit only supports one value; using " +
                            "overridePins=false for all " +
                            "connections");
                } else {
                    lastOverridePinsEncountered = currentOverridePins;
                }

                // Parse the supplied certificate file
                String caPathFromUser = parser.getAttributeValue(null, "src").trim();

                // Parse the path to the certificate bundle for src=@raw - we ignore system or user
                // as the src
                if (!TextUtils.isEmpty(caPathFromUser) && !caPathFromUser.equals("user")
                        && !caPathFromUser.equals("system") && caPathFromUser.startsWith("@raw")) {

                    InputStream stream =
                            context.getResources().openRawResource(
                                    context.getResources().getIdentifier(
                                            caPathFromUser.split("/")[1], "raw",
                                            context.getPackageName()));

                    debugCaCertificates.add(CertificateFactory.getInstance("X.509")
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
        if (debugCaCertificates.size() > 0) {
            result.debugCaCertificates = debugCaCertificates;
        }
        return result;
    }
}
