package com.datatheorem.android.trustkit.config;


import android.support.test.runner.AndroidJUnit4;

import com.datatheorem.android.trustkit.pinning.PublicKeyPin;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;


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
        DomainPinningPolicy policy = new DomainPinningPolicy("www.test.com", true, pins, true,
                date, reportUris, false);

        assertEquals("www.test.com", policy.getHostname());
        assertEquals(date, policy.getExpirationDate());

        Set<PublicKeyPin> expectedPins = new HashSet<>();
        for (String pinStr : pins) {
            expectedPins.add(new PublicKeyPin(pinStr));

        }
        assertEquals(expectedPins, policy.getPublicKeyHashes());

        // Ensure the default report URI was added as shouldDisableDefaultReportUri is false
        Set<URL> expectedReportUris = new HashSet<>();
        for (String uriStr : reportUris) {
            expectedReportUris.add(new URL(uriStr));
        }
        expectedReportUris.add(new URL("https://overmind.datatheorem.com/trustkit/report"));
        assertEquals(expectedReportUris, policy.getReportUris());

        assertTrue(policy.shouldEnforcePinning());
        assertTrue(policy.shouldIncludeSubdomains());
    }

    @Test
    public void testValidPolicyInternationalizeHostname() throws MalformedURLException {
        DomainPinningPolicy policy = new DomainPinningPolicy("českárepublika.icom.museum", true,
                pins, true, date, reportUris, false);

        assertEquals(policy.getHostname(), "českárepublika.icom.museum");
    }

    @Test
    public void testBadPolicyOnlyOnePin() throws MalformedURLException {
        Set<String> badPins = new HashSet<>();
        badPins.add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

        boolean didReceiveConfigError = false;
        try {
            DomainPinningPolicy policy = new DomainPinningPolicy("www.test.com", true, badPins,
                    true, date, reportUris, false);
        }
        catch (ConfigurationException e) {
            if (e.getMessage().startsWith("Less than two pins")) {
                didReceiveConfigError = true;
            } else {
                throw e;
            }
        }
        assertTrue(didReceiveConfigError);
    }

    @Test
    public void testBadPolicyPinTld() throws MalformedURLException {
        boolean didReceiveConfigError = false;
        try {
            DomainPinningPolicy policy = new DomainPinningPolicy("com", true, pins, true,
                    date, reportUris, false);
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
