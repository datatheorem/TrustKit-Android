package com.datatheorem.android.trustkit.config;

import android.content.res.XmlResourceParser;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

public class TrustKitConfiguration extends HashMap<String, PinnedDomainConfiguration> {
    // TODO(ad): Investigate whether we can add TSKIgnorePinningForUserDefinedTrustAnchors and TSKSwizzleNetworkDelegates

    // TODO(ad): Implement the same sanity checks as https://github.com/datatheorem/TrustKit/blob/master/TrustKit/parse_configuration.m
    public static TrustKitConfiguration fromXmlPolicy(XmlResourceParser parser) {
        TrustKitConfiguration trustKitConfiguration = new TrustKitConfiguration();
        String domainName = null;
        PinnedDomainConfiguration.Builder pinnedDomainConfigBuilder = new PinnedDomainConfiguration.Builder();
        ArrayList<String> knownPins = null;
        boolean isADomain = false;
        boolean isAPin = false;
        boolean isAReportUri = false;
        ArrayList<String> reportUris = null;
        try {
            int eventType = parser.getEventType();
            while (eventType != XmlPullParser.END_DOCUMENT) {
                if (eventType == XmlPullParser.START_TAG) {
                    if ("domain".equals(parser.getName())){
                        isADomain = true;
                        pinnedDomainConfigBuilder
                                .includeSubdomains(parser.getAttributeBooleanValue(0, false));
                    } else if ("pin".equals(parser.getName())) {
                        isAPin = true;
                        isADomain = false;
                        if (knownPins == null) {
                            knownPins = new ArrayList<>();
                        }
                    } else if ("report-uri".equals(parser.getName())) {
                        isAReportUri = true;
                        isAPin = false;
                        isADomain = false;
                        if (reportUris == null) {
                            reportUris = new ArrayList<>();
                        }
                    }
                } else if (eventType == XmlPullParser.END_TAG) {
                    if ("domain".equals(parser.getName())) {
                        isADomain = false;
                    }

                    if ("pin".equals(parser.getName())) {
                        isAPin = false;
                    }


                    if ("report-uri".equals(parser.getName())){
                        isAReportUri = false;
                    }

                    if ("domain-config".equals(parser.getName())){
                        pinnedDomainConfigBuilder
                                .reportURIs(reportUris.toArray(new String[reportUris.size()]))
                                .publicKeyHashes(knownPins.toArray(new String[knownPins.size()]));
                        trustKitConfiguration.put(domainName, pinnedDomainConfigBuilder.build());
                    }


                } else if (eventType == XmlPullParser.TEXT) {
                    if (isADomain){
                        domainName = parser.getText();
                    }

                    if (isAPin) {
                        knownPins.add(parser.getText());
                    }

                    if (isAReportUri) {
                        reportUris.add(parser.getText());
                    }
                }

                eventType = parser.next();
            }

            if (trustKitConfiguration.size() < 0) {
                throw new ConfigurationException("something wrong with your configuration");
            }

            return trustKitConfiguration;

        } catch (XmlPullParserException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
