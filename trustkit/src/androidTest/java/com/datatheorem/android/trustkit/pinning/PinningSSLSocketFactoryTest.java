package com.datatheorem.android.trustkit.pinning;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.datatheorem.android.trustkit.CertificateUtils;
import com.datatheorem.android.trustkit.PinningValidationResult;
import com.datatheorem.android.trustkit.TestableTrustKit;
import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;

import static junit.framework.Assert.assertTrue;
import static junit.framework.Assert.assertFalse;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@RunWith(AndroidJUnit4.class)
public class PinningSSLSocketFactoryTest {

    @Mock
    private BackgroundReporter mockReporter;

    // The root CA for cacert.org; useful to test connections with a custom CA
    private final String caCertDotOrgRootPem =
            "MIIHPTCCBSWgAwIBAgIBADANBgkqhkiG9w0BAQQFADB5MRAwDgYDVQQKEwdSb290\n" +
                    "IENBMR4wHAYDVQQLExVodHRwOi8vd3d3LmNhY2VydC5vcmcxIjAgBgNVBAMTGUNB\n" +
                    "IENlcnQgU2lnbmluZyBBdXRob3JpdHkxITAfBgkqhkiG9w0BCQEWEnN1cHBvcnRA\n" +
                    "Y2FjZXJ0Lm9yZzAeFw0wMzAzMzAxMjI5NDlaFw0zMzAzMjkxMjI5NDlaMHkxEDAO\n" +
                    "BgNVBAoTB1Jvb3QgQ0ExHjAcBgNVBAsTFWh0dHA6Ly93d3cuY2FjZXJ0Lm9yZzEi\n" +
                    "MCAGA1UEAxMZQ0EgQ2VydCBTaWduaW5nIEF1dGhvcml0eTEhMB8GCSqGSIb3DQEJ\n" +
                    "ARYSc3VwcG9ydEBjYWNlcnQub3JnMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\n" +
                    "CgKCAgEAziLA4kZ97DYoB1CW8qAzQIxL8TtmPzHlawI229Z89vGIj053NgVBlfkJ\n" +
                    "8BLPRoZzYLdufujAWGSuzbCtRRcMY/pnCujW0r8+55jE8Ez64AO7NV1sId6eINm6\n" +
                    "zWYyN3L69wj1x81YyY7nDl7qPv4coRQKFWyGhFtkZip6qUtTefWIonvuLwphK42y\n" +
                    "fk1WpRPs6tqSnqxEQR5YYGUFZvjARL3LlPdCfgv3ZWiYUQXw8wWRBB0bF4LsyFe7\n" +
                    "w2t6iPGwcswlWyCR7BYCEo8y6RcYSNDHBS4CMEK4JZwFaz+qOqfrU0j36NK2B5jc\n" +
                    "G8Y0f3/JHIJ6BVgrCFvzOKKrF11myZjXnhCLotLddJr3cQxyYN/Nb5gznZY0dj4k\n" +
                    "epKwDpUeb+agRThHqtdB7Uq3EvbXG4OKDy7YCbZZ16oE/9KTfWgu3YtLq1i6L43q\n" +
                    "laegw1SJpfvbi1EinbLDvhG+LJGGi5Z4rSDTii8aP8bQUWWHIbEZAWV/RRyH9XzQ\n" +
                    "QUxPKZgh/TMfdQwEUfoZd9vUFBzugcMd9Zi3aQaRIt0AUMyBMawSB3s42mhb5ivU\n" +
                    "fslfrejrckzzAeVLIL+aplfKkQABi6F1ITe1Yw1nPkZPcCBnzsXWWdsC4PDSy826\n" +
                    "YreQQejdIOQpvGQpQsgi3Hia/0PsmBsJUUtaWsJx8cTLc6nloQsCAwEAAaOCAc4w\n" +
                    "ggHKMB0GA1UdDgQWBBQWtTIb1Mfz4OaO873SsDrusjkY0TCBowYDVR0jBIGbMIGY\n" +
                    "gBQWtTIb1Mfz4OaO873SsDrusjkY0aF9pHsweTEQMA4GA1UEChMHUm9vdCBDQTEe\n" +
                    "MBwGA1UECxMVaHR0cDovL3d3dy5jYWNlcnQub3JnMSIwIAYDVQQDExlDQSBDZXJ0\n" +
                    "IFNpZ25pbmcgQXV0aG9yaXR5MSEwHwYJKoZIhvcNAQkBFhJzdXBwb3J0QGNhY2Vy\n" +
                    "dC5vcmeCAQAwDwYDVR0TAQH/BAUwAwEB/zAyBgNVHR8EKzApMCegJaAjhiFodHRw\n" +
                    "czovL3d3dy5jYWNlcnQub3JnL3Jldm9rZS5jcmwwMAYJYIZIAYb4QgEEBCMWIWh0\n" +
                    "dHBzOi8vd3d3LmNhY2VydC5vcmcvcmV2b2tlLmNybDA0BglghkgBhvhCAQgEJxYl\n" +
                    "aHR0cDovL3d3dy5jYWNlcnQub3JnL2luZGV4LnBocD9pZD0xMDBWBglghkgBhvhC\n" +
                    "AQ0ESRZHVG8gZ2V0IHlvdXIgb3duIGNlcnRpZmljYXRlIGZvciBGUkVFIGhlYWQg\n" +
                    "b3ZlciB0byBodHRwOi8vd3d3LmNhY2VydC5vcmcwDQYJKoZIhvcNAQEEBQADggIB\n" +
                    "ACjH7pyCArpcgBLKNQodgW+JapnM8mgPf6fhjViVPr3yBsOQWqy1YPaZQwGjiHCc\n" +
                    "nWKdpIevZ1gNMDY75q1I08t0AoZxPuIrA2jxNGJARjtT6ij0rPtmlVOKTV39O9lg\n" +
                    "18p5aTuxZZKmxoGCXJzN600BiqXfEVWqFcofN8CCmHBh22p8lqOOLlQ+TyGpkO/c\n" +
                    "gr/c6EWtTZBzCDyUZbAEmXZ/4rzCahWqlwQ3JNgelE5tDlG+1sSPypZt90Pf6DBl\n" +
                    "Jzt7u0NDY8RD97LsaMzhGY4i+5jhe1o+ATc7iwiwovOVThrLm82asduycPAtStvY\n" +
                    "sONvRUgzEv/+PDIqVPfE94rwiCPCR/5kenHA0R6mY7AHfqQv0wGP3J8rtsYIqQ+T\n" +
                    "SCX8Ev2fQtzzxD72V7DX3WnRBnc0CkvSyqD/HMaMyRa+xMwyN2hzXwj7UfdJUzYF\n" +
                    "CpUCTPJ5GhD22Dp1nPMd8aINcGeGG7MW9S/lpOt5hvk9C8JzC6WZrG/8Z7jlLwum\n" +
                    "GCSNe9FINSkYQKyTYOGWhlC0elnYjyELn8+CkcY7v2vcB5G5l1YjqrZslMZIBjzk\n" +
                    "zk6q5PYvCdxTby78dOs6Y5nCpqyJvKeyRKANihDjbPIky/qbn3BHLt4Ui9SyIAmW\n" +
                    "omTxJBzcoTWcFbLUvFUufQb1nA5V9FrWk9p2rSVzTMVD\n";
    private final Certificate caCertDotOrgRoot
            = CertificateUtils.certificateFromPem(caCertDotOrgRootPem);

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @After
    public void tearDown() {
        TestableTrustKit.reset();
        TestableTrustManagerBuilder.reset();
    }

    //region Tests for when the domain is pinned
    @Test
    public void testPinnedDomainExpiredChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "expired.badssl.com";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname(serverHostname)
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if ((e.getCause() instanceof CertificateException
                    && !(e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceiveHandshakeError = true;
            }
        }
        assertTrue(didReceiveHandshakeError);

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getConfigForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }

    @Test
    public void testPinnedDomainWrongHostnameChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "wrong.host.badssl.com";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname(serverHostname)
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if ((e.getCause() instanceof CertificateException
                    && !(e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceiveHandshakeError = true;
            }
        }
        assertTrue(didReceiveHandshakeError);

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getConfigForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }

    @Test
    public void testPinnedDomainSuccess() throws IOException {
        String serverHostname = "www.datatheorem.com";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname(serverHostname)
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Valid pin
                    add("grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection succeeds
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        test.createSocket(serverHostname, 443);

        // Ensure the background reporter was NOT called
        verify(mockReporter, never()).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getConfigForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED)
        );
    }

    @Test
    public void testPinnedDomainInvalidPin() throws IOException {
        String serverHostname = "www.yahoo.com";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname(serverHostname)
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if ((e.getCause() instanceof CertificateException
                    && (e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceiveHandshakeError = true;
            }
        }
        assertTrue(didReceiveHandshakeError);

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getConfigForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED)
        );
    }

    @Test
    public void testPinnedDomainInvalidPinAndPinningNotEnforced() throws IOException {
        String serverHostname = "www.github.com";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname(serverHostname)
                .setShouldEnforcePinning(false)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection succeeds
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        test.createSocket(serverHostname, 443);

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getConfigForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED)
        );
    }

    @Test
    public void testPinnedDomainUntrustedChainAndPinningNotEnforced() throws IOException {
        String serverHostname = "untrusted-root.badssl.com";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname(serverHostname)
                .setShouldEnforcePinning(false)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if ((e.getCause() instanceof CertificateException
                    && !(e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceiveHandshakeError = true;
            }
        }

        // Ensure the SSL handshake failed
        assertTrue(didReceiveHandshakeError);

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getConfigForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }

    @Test
    public void testDebugOverridesInvalidPinButOverridePins() throws IOException, CertificateException {
        String serverHostname = "www.cacert.org";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname(serverHostname)
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        // Create a configuration with debug overrides enabled to add the cacert.org CA and to set
        // overridePins to true
        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                true,
                new HashSet<Certificate>(){{ add(caCertDotOrgRoot); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection succeeds
        // This means that debug-overrides properly enables the supplied debug CA cert and
        // disables pinning when overridePins is true
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        test.createSocket(serverHostname, 443);

        // Ensure the background reporter was NOT called
        verify(mockReporter, never()).pinValidationFailed(
                anyString(),
                anyInt(),
                (List<X509Certificate>) any(),
                (List<X509Certificate>) any(),
                any(DomainPinningPolicy.class),
                any(PinningValidationResult.class)
        );
    }

    @Test
    public void testDebugOverridesButAppNotDebuggable() throws IOException, CertificateException {
        if (Build.VERSION.SDK_INT >= 24) {
            // This test will not work when using the Android N XML network policy because we can't
            // dynamically switch the App's debuggable flag for true to false (it is always true
            // when running the test suite)
            return;
        }
        String serverHostname = "www.cacert.org";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname(serverHostname)
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        // Create a configuration with debug overrides enabled to add the cacert.org CA but
        // make the App's debuggable flag disabled to mock a production App
        Context mockContext = InstrumentationRegistry.getContext();
        int originalAppFlags = mockContext.getApplicationInfo().flags;
        mockContext.getApplicationInfo().flags = 0;
        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                true,
                new HashSet<Certificate>(){{ add(caCertDotOrgRoot); }},
                mockContext,
                mockReporter);
        mockContext.getApplicationInfo().flags = originalAppFlags;

        // Create an TrustKitSSLSocketFactory and ensure connection fails
        // This means that debug-overrides property was ignored because the App is not debuggable
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            didReceiveHandshakeError = true;
        }
        assertTrue(didReceiveHandshakeError);

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getConfigForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }

    @Test
    public void testDebugOverridesInvalidPin() throws IOException, CertificateException {
        if (Build.VERSION.SDK_INT >= 24) {
            // This test will not work when using the Android N XML network policy because we can't
            // dynamically switch overridePins to false (as it is true in the XML policy)
            return;
        }
        String serverHostname = "www.cacert.org";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname(serverHostname)
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        // Create a configuration with debug overrides enabled to add the cacert.org CA and to set
        // overridePins to false, making the connection fail
        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                false,
                new HashSet<Certificate>(){{ add(caCertDotOrgRoot); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection fails
        // This means that debug-overrides properly enables the supplied debug CA cert but does not
        // disable pinning when overridePins is false
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if ((e.getCause() instanceof CertificateException
                    && (e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceiveHandshakeError = true;
            }
        }
        assertTrue(didReceiveHandshakeError);

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getConfigForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED)
        );
    }
    //endregion

    //region Tests for when the domain is NOT pinned
    @Test
    public void testNonPinnedDomainUntrustedRootChain() throws IOException {
        if (Build.VERSION.SDK_INT >= 24) {
            // This test will not work when using the Android N XML network policy because we can't
            // dynamically remove the debug-overrides tag defined in the XML policy which adds the
            // cacert.org CA cert as a trusted CA
            return;
        }
        String serverHostname = "www.cacert.org";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname("other.domain.com")
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection fails
        // This means that TrustKit does not interfere with default certificate validation
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if ((e.getCause() instanceof CertificateException
                    && !(e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceiveHandshakeError = true;
            }
        }
        assertTrue(didReceiveHandshakeError);

        // Ensure the background reporter was NOT called as we only want reports for pinned domains
        verify(mockReporter, never()).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getConfigForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED)
        );
    }

    @Test
    public void testNonPinnedDomainSuccess() throws IOException {
        // Initialize TrustKit
        String serverHostname = "www.google.com";
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname("other.domain.com")
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection succeeds
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        test.createSocket(serverHostname, 443);

        // Ensure the background reporter was NOT called
        verify(mockReporter, never()).pinValidationFailed(
                anyString(),
                anyInt(),
                (List<X509Certificate>) any(),
                (List<X509Certificate>) any(),
                any(DomainPinningPolicy.class),
                any(PinningValidationResult.class)
        );
    }

    @Test
    public void testDebugOverrides() throws IOException, CertificateException {
        String serverHostname = "www.cacert.org";
        // Create a policy for a different domain
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname("other.domain.com")
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        // Create a configuration with debug overrides enabled to add the cacert.org CA
        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                false,
                new HashSet<Certificate>(){{ add(caCertDotOrgRoot); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection succeeds
        // This means that debug-overrides properly enables the supplied debug CA cert
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        test.createSocket(serverHostname, 443);

        // Ensure the background reporter was NOT called
        verify(mockReporter, never()).pinValidationFailed(
                anyString(),
                anyInt(),
                (List<X509Certificate>) any(),
                (List<X509Certificate>) any(),
                any(DomainPinningPolicy.class),
                any(PinningValidationResult.class)
        );
    }

    @Test
    public void testDebugOverridesSystemCa() throws IOException, CertificateException {
        String serverHostname = "www.google.com";
        // Create a policy for a different domain
        final DomainPinningPolicy domainPolicy = new DomainPinningPolicy.Builder()
                .setHostname("other.domain.com")
                .setShouldEnforcePinning(true)
                .setPublicKeyHashes(new HashSet<String>() {{
                    // Wrong pins
                    add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
                    add("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=");
                }}).build();

        // Create a configuration with debug overrides enabled to add the cacert.org CA
        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                false,
                new HashSet<Certificate>(){{ add(caCertDotOrgRoot); }},
                InstrumentationRegistry.getContext(),
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection succeeds
        // This means that debug-overrides does not disable the System CAs
        SSLSocketFactory test = new TrustKitSSLSocketFactory();
        test.createSocket(serverHostname, 443);

        // Ensure the background reporter was NOT called
        verify(mockReporter, never()).pinValidationFailed(
                anyString(),
                anyInt(),
                (List<X509Certificate>) any(),
                (List<X509Certificate>) any(),
                any(DomainPinningPolicy.class),
                any(PinningValidationResult.class)
        );
    }
    //endregion
}
