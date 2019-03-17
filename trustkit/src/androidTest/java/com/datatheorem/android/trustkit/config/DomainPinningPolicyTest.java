package com.datatheorem.android.trustkit.config;


import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

import android.support.test.runner.AndroidJUnit4;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;


@RunWith(AndroidJUnit4.class)
public class DomainPinningPolicyTest {

    private final static Set<String> pins = new HashSet<>();
    static {
        pins.add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        pins.add("rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=");
    }

    private final static Set<String> reportUris = new HashSet<>();
    static {
        reportUris.add("https://www.test.com");
        reportUris.add("https://www.test2.com");
    }

    private final static Date date = new Date();

    @Test
    public void testValidPolicy() throws MalformedURLException {
        // Given a valid policy for a domain
        // When parsing it, it succeeds
        DomainPinningPolicy policy = new DomainPinningPolicy(
                "www.test.com", true, pins, true, date, reportUris, false
        );
        // And the right configuration was saved
        assertEquals("www.test.com", policy.getHostname());
        assertEquals(date, policy.getExpirationDate());
        assertTrue(policy.shouldEnforcePinning());
        assertTrue(policy.shouldIncludeSubdomains());

        // And right pins were saved
        Set<PublicKeyPin> expectedPins = new HashSet<>();
        for (String pinStr : pins) {
            expectedPins.add(new PublicKeyPin(pinStr));

        }
        assertEquals(expectedPins, policy.getPublicKeyPins());

        // And the default report URI was added as shouldDisableDefaultReportUri is false
        Set<URL> expectedReportUris = new HashSet<>();
        for (String uriStr : reportUris) {
            expectedReportUris.add(new URL(uriStr));
        }
        expectedReportUris.add(new URL("https://overmind.datatheorem.com/trustkit/report"));
        assertEquals(expectedReportUris, policy.getReportUris());
    }

    @Test
    public void testValidPolicyInternationalizeHostname() throws MalformedURLException {
        // Given a valid policy for a domain name with international characters
        String internationalDomain = "českárepublika.icom.museum";

        // When parsing it, it succeeds
        DomainPinningPolicy policy = new DomainPinningPolicy(
                internationalDomain, true, pins, true, date, reportUris, false
        );
        assertEquals(policy.getHostname(), internationalDomain);
    }
        );
        assertEquals(policy.getHostname(), "českárepublika.icom.museum");
    }

    @Test
    public void testBadPolicyOnlyOnePin() throws MalformedURLException {
        // Given a bad policy for a domain that only has one pin
        Set<String> badPins = new HashSet<>();
        badPins.add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

        // When parsing it, it fails
        boolean didReceiveConfigError = false;
        try {
            new DomainPinningPolicy("www.test.com", true, badPins, true, date, reportUris, false);
        } catch (ConfigurationException e) {
            if (e.getMessage().startsWith("Less than two pins")) {
                didReceiveConfigError = true;
            } else {
                throw e;
            }
        }
        assertTrue(didReceiveConfigError);
    }

    
    @Test
    public void testNoPinsButPinningEnforceDisabledShouldBeValid() throws MalformedURLException {
        // Given a bad policy for a domain that has one pins at all
        Set<String> emptyPins = new HashSet<>();
        boolean didReceivedConfigError = false;

        // When parsing it, it fails
        try {
            new DomainPinningPolicy("www.test.com", true, emptyPins, true, date, reportUris, false);
        } catch (ConfigurationException e) {
            if (e.getMessage().startsWith("An empty pin-set")) {
                didReceivedConfigError = true;
            } else {
                throw e;
            }
        }
        assertTrue(didReceivedConfigError);
    }

    @Test
    public void testBadPolicyPinTld() throws MalformedURLException {
        // Given a policy for an invalid domain
        String badDomain = ".com";

        // When parsing it, it fails
        boolean didReceiveConfigError = false;
        try {
            new DomainPinningPolicy(badDomain, true, pins, true, date, reportUris, false);
        }
        catch (ConfigurationException e) {
            if (e.getMessage().startsWith("Tried to pin an invalid domain")) {
                didReceiveConfigError = true;
            } else {
                throw e;
            }
        }
        assertTrue(didReceiveConfigError);
    }
}
