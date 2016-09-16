package com.datatheorem.android.trustkit;

import android.content.res.XmlResourceParser;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.datatheorem.android.trustkit.config.ConfigurationException;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public final class TrustKitConfiguration extends HashSet<PinnedDomainConfiguration> {
    // TODO(ad): Investigate whether we can add TSKIgnorePinningForUserDefinedTrustAnchors and TSKSwizzleNetworkDelegates

    /**
     * Return a configuration or null if the specified domain is not pinned.
     * @param serverHostname
     * @return
     */
    @Nullable
    public PinnedDomainConfiguration findConfiguration(@NonNull String serverHostname) {
        for (PinnedDomainConfiguration pinnedDomainConfiguration : this) {
            // TODO(ad): Handle includeSubdomains here

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
        String domainName = null;
        PinnedDomainConfiguration.Builder pinnedDomainConfigBuilder =
                new PinnedDomainConfiguration.Builder();
        Set<String> knownPins = null;
        boolean enforcePinning = false;
        boolean disableDefaultReportUri = false;
        ArrayList<String> reportUris = null;
        Date expirationDate = null;

        boolean isATagDomain = false;
        boolean isATagPin = false;
        boolean isATagReportUri = false;

        int eventType = parser.getEventType();
        while (eventType != XmlPullParser.END_DOCUMENT) {
            if (eventType == XmlPullParser.START_TAG) {
                if ("domain".equals(parser.getName())){
                    isATagDomain = true;
                    pinnedDomainConfigBuilder
                            .includeSubdomains(parser.getAttributeBooleanValue(0, false));
                } else if ("pin".equals(parser.getName())) {
                    isATagPin = true;
                    if (knownPins == null) {
                        knownPins = new HashSet<>();
                    }
                } else if ("trustkit-config".equals(parser.getName())) {
                    enforcePinning = parser.getAttributeBooleanValue(null, "enforcePinning", false);
                    disableDefaultReportUri =
                            parser.getAttributeBooleanValue(null, "disableDefaultReportUri", false);
                } else if ("pin-set".equals(parser.getName())) {
                    SimpleDateFormat df = new SimpleDateFormat("YYYY-MM-DD", Locale.getDefault());
                    String expirationDateAttr = parser.getAttributeValue(null, "expiration");
                    if (expirationDateAttr != null) {
                        expirationDate =  df.parse(expirationDateAttr);
                    }
                } else if ("report-uri".equals(parser.getName())) {
                    isATagReportUri = true;
                    isATagPin = false;
                    isATagDomain = false;
                    if (reportUris == null) {
                        reportUris = new ArrayList<>();
                    }
                }
            } else if (eventType == XmlPullParser.END_TAG) {
                if ("domain".equals(parser.getName())) {
                    isATagDomain = false;
                }

                if ("pin".equals(parser.getName())) {
                    isATagPin = false;
                }

                if ("report-uri".equals(parser.getName())){
                    isATagReportUri = false;
                }

                if ("domain-config".equals(parser.getName())){
                    pinnedDomainConfigBuilder
                            .pinnedDomainName(domainName)
                            .enforcePinning(enforcePinning)
                            .disableDefaultReportUri(disableDefaultReportUri)
                            .publicKeyHashes(knownPins);

                    if (reportUris != null) {
                        pinnedDomainConfigBuilder
                                .reportURIs(reportUris.toArray(new String[reportUris.size()]));
                    }

                    if (expirationDate != null) {
                        pinnedDomainConfigBuilder.expirationDate(expirationDate);
                    }


                    trustKitConfiguration.add(pinnedDomainConfigBuilder.build());
                    domainName = "";
                    enforcePinning = false;
                    disableDefaultReportUri = false;
                    knownPins = null;
                    expirationDate = null;
                }
            } else if (eventType == XmlPullParser.TEXT) {
                if (isATagDomain){
                    domainName = parser.getText();
                }

                if (isATagPin) {
                    knownPins.add(parser.getText());
                }

                if (isATagReportUri) {
                    reportUris.add(parser.getText());
                }
            }

            eventType = parser.next();
        }

        if (trustKitConfiguration.size() < 0) {
            throw new ConfigurationException("something wrong with your configuration");
        }

        return trustKitConfiguration;
    }
}
