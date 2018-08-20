package com.datatheorem.android.trustkit;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;

import android.content.Context;
import android.content.res.Resources;
import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;
import com.datatheorem.android.trustkit.config.ConfigurationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class TrustKitTest {

    @Before
    public void setUp() {
        TestableTrustKit.reset();
    }

    @Test
    public void testInitializeWithDefaultXmlFile() {
        Context context = InstrumentationRegistry.getContext();
        TrustKit trustkit = TrustKit.initializeWithNetworkSecurityConfiguration(context);
        assertNotNull(trustkit);
        assertNotNull(TrustKit.getInstance());
        assertNotNull(trustkit.getConfiguration());
        assertNotNull(trustkit.getSSLSocketFactory("www.datatheorem.com"));
        assertNotNull(trustkit.getTrustManager("www.datatheorem.com"));

        // Initialize again and ensure it fails
        boolean didInitFail = false;
        try {
            TrustKit.initializeWithNetworkSecurityConfiguration(context);
        } catch (IllegalStateException e) {
            didInitFail = true;
        }
        assertTrue(didInitFail);
    }

    @Test
    public void testInitializeWithValidXmlFile() {
        Context context = InstrumentationRegistry.getContext();
        int networkSecurityConfigId = context.getResources().getIdentifier(
                "network_security_config", "xml", context.getPackageName());
        TrustKit trustkit = TrustKit.initializeWithNetworkSecurityConfiguration(context,
                networkSecurityConfigId);
        assertNotNull(trustkit);
    }

    @Test
    public void testInitializeWithBadXmlFile() {
        Context context = InstrumentationRegistry.getContext();
        int pemFileId = context.getResources().getIdentifier("bad_config", "xml",
                context.getPackageName());

        boolean didInitFail = false;
        try {
            TrustKit.initializeWithNetworkSecurityConfiguration(context, pemFileId);
        } catch (ConfigurationException e) {
            didInitFail = true;
        }
        assertTrue(didInitFail);
    }

    @Test
    public void testInitializeWithBadResourceId() {
        Context context = InstrumentationRegistry.getContext();

        boolean didInitFail = false;
        try {
            TrustKit.initializeWithNetworkSecurityConfiguration(context, 0);
        } catch (ConfigurationException e) {
            // Specific error on Android N because the res ID will not match the App's manifest
            if (Build.VERSION.SDK_INT >= 24) {
                didInitFail = true;
            }
        } catch (Resources.NotFoundException e) {
            didInitFail = true;
        }
        assertTrue(didInitFail);
    }

    @Test
    public void testInitializeWithBadFile() {
        Context context = InstrumentationRegistry.getContext();
        int pemFileId = context.getResources().getIdentifier("cacertorg", "raw",
                context.getPackageName());

        boolean didInitFail = false;
        try {
            TrustKit.initializeWithNetworkSecurityConfiguration(context, pemFileId);
        } catch (ConfigurationException e) {
            if (e.getMessage().contains("different network policy")) {
                // Specific error on Android N because the res ID will not match the App's manifest
                if (Build.VERSION.SDK_INT >= 24) {
                    didInitFail = true;
                }
            }
        } catch (Resources.NotFoundException e) {
            didInitFail = true;
        }
        assertTrue(didInitFail);
    }
}
