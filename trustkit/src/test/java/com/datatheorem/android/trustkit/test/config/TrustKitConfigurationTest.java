package com.datatheorem.android.trustkit.test.config;

import android.content.pm.PackageManager;

import com.datatheorem.android.trustkit.BuildConfig;
import com.datatheorem.android.trustkit.TrustKitConfiguration;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.annotation.Config;

import java.io.IOException;
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
                .enforcePinning(false)
                .disableDefaultReportUri(true)
                .includeSubdomains(false)
                .publicKeyHashes(pins)
                .pinnedDomainName("www.test.com")
                .build();

        domainName = mockPinnedDomainConfiguration.getNotedHostname();
        trustKitConfiguration.add(mockPinnedDomainConfiguration);

    }

    @Test
    public void getByPinnedHostnameTest_HappyCase() {
        Assert.assertNotNull(trustKitConfiguration.getByPinnedHostname(domainName));
        Assert.assertEquals(mockPinnedDomainConfiguration, trustKitConfiguration.getByPinnedHostname(domainName));
    }

    @Test
    public void getByPinnedHostnameTest_SadCase() {
        Assert.assertNull(trustKitConfiguration.getByPinnedHostname("www.toto.com"));
    }
}
