package com.datatheorem.android.trustkit;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.datatheorem.android.trustkit.reporting.BackgroundReporter;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.UUID;


@RunWith(AndroidJUnit4.class)
public class BackgroundReporterTest {
    private BackgroundReporter backgroundReporter;

    @Before
    public void setUp() throws Exception {
        Context context = InstrumentationRegistry.getContext();

        this.backgroundReporter =
                new BackgroundReporter(false, context.getPackageName(),
                        context.getPackageManager().getPackageInfo(context.getPackageName(), 0)
                                .versionName, UUID.randomUUID().toString());

        TestableTrustKit.initWithNetworkPolicy(context);

    }


    /*
     * We test the 2 results of a pinValidationFailed call - Happy Case, no exception
     */
    @Test
    public void testPinValidationFailed_HappyCase() throws Exception {
        ArrayList<X509Certificate> certChain =
        (ArrayList<X509Certificate>)(ArrayList<?>)TestableTrustKit.getInstance().getConfiguration().getDebugCaCertificates();

        TestableTrustKit.getInstance()
                .getReporter().pinValidationFailed("untrusted-root.badssl.com", 443, certChain,
                certChain,
                TestableTrustKit.getInstance().getConfiguration()
                .getConfigForHostname("untrusted-root.badssl.com"),
                PinningValidationResult.FAILED);

    }
}


