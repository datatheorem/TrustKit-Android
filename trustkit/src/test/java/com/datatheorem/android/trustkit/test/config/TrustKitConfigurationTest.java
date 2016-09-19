package com.datatheorem.android.trustkit.test.config;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.TrustKitConfiguration;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.annotation.Config;

import java.util.HashSet;
import java.util.Set;

@Config(constants = BuildConfig.class)
@RunWith(RobolectricGradleTestRunner.class)
public class TrustKitConfigurationTest {


    PinnedDomainConfiguration mockPinnedDomainConfiguration;
    String domainName;
    TrustKitConfiguration trustKitConfiguration;

    @Before
    public void setUp() {
        trustKitConfiguration = new TrustKitConfiguration();
        String pin = "pin-sha256=\"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=\"";
        String pin2 = "pin-sha256=\"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8=\"";
        Set<String> pins = new HashSet<>();
        pins.add(pin);
        pins.add(pin2);
        mockPinnedDomainConfiguration = new PinnedDomainConfiguration.Builder()
                .shouldEnforcePinning(false)
                .shouldDisableDefaultReportUri(true)
                .shouldIncludeSubdomains(false)
                .publicKeyHashes(pins)
                .pinnedDomainName("www.test.com")
                .build();

        domainName = mockPinnedDomainConfiguration.getNotedHostname();
        trustKitConfiguration.getPinnedDomainConfigurations().add(mockPinnedDomainConfiguration);

    }

    @Test
    public void getByPinnedHostnameTest_HappyCase() {
        Assert.assertNotNull(trustKitConfiguration.findConfiguration(domainName));
        Assert.assertEquals(mockPinnedDomainConfiguration, trustKitConfiguration.findConfiguration(domainName));
    }

    @Test
    public void getByPinnedHostnameTest_SadCase() {
        Assert.assertNull(trustKitConfiguration.findConfiguration("www.toto.com"));
    }
}
