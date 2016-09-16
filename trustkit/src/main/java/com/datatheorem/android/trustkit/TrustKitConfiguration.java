package com.datatheorem.android.trustkit;

import android.content.res.XmlResourceParser;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.datatheorem.android.trustkit.config.ConfigurationException;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class TrustKitConfiguration extends HashSet<PinnedDomainConfiguration> {
    // TODO(ad): Investigate whether we can add TSKIgnorePinningForUserDefinedTrustAnchors and TSKSwizzleNetworkDelegates

    @Nullable
    public PinnedDomainConfiguration findConfiguration(@NonNull String serverHostname) {
        for (PinnedDomainConfiguration pinnedDomainConfiguration : this) {
            // TODO(ad): Handle includeSubdomains here
            if (serverHostname.equals(pinnedDomainConfiguration.getNotedHostname())) {
                return pinnedDomainConfiguration;
            }
        }
        return null;
    }

    protected static TrustKitConfiguration fromXmlPolicy(XmlResourceParser parser)
            throws XmlPullParserException, IOException {
        TrustKitConfiguration trustKitConfiguration = new TrustKitConfiguration();
        String domainName = null;
        PinnedDomainConfiguration.Builder pinnedDomainConfigBuilder =
                new PinnedDomainConfiguration.Builder();
        Set<String> knownPins = null;
        boolean enforcePinning = false;
        boolean disableDefaultReportUri = false;
        ArrayList<String> reportUris = null;

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


                    trustKitConfiguration.add(pinnedDomainConfigBuilder.build());
                    domainName = "";
                    enforcePinning = false;
                    disableDefaultReportUri = false;
                    knownPins = null;
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
