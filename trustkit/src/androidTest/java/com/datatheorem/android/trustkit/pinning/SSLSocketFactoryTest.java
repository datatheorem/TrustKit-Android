package com.datatheorem.android.trustkit.pinning;

import android.content.Context;
import android.os.Build;

import androidx.test.platform.app.InstrumentationRegistry;

import com.datatheorem.android.trustkit.CertificateUtils;
import com.datatheorem.android.trustkit.TestableTrustKit;
import com.datatheorem.android.trustkit.config.DomainPinningPolicy;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.android.gms.security.ProviderInstaller;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;

import static junit.framework.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;


/**
 * Tests TrustKit's SSLSocketFactory.
 *
 * The general testing strategy used here is to connect to live websites. This provides a variety of
 * valid certificate chains that can then have different pins applied to each. This requires no
 * special mock servers or mock CA setup, but it is dependent on the domains being live and having
 * valid certificate chains.
 */
@SuppressWarnings("unchecked")
public class SSLSocketFactoryTest {

    @Mock
    private BackgroundReporter mockReporter;

    // The root CA for cacert.org; useful to test connections with a custom CA
    private final String caCertDotOrgRootPem =
            "MIIHbDCCBVSgAwIBAgIDAsGhMA0GCSqGSIb3DQEBDQUAMFQxFDASBgNVBAoTC0NB\n" +
                    "Y2VydCBJbmMuMR4wHAYDVQQLExVodHRwOi8vd3d3LkNBY2VydC5vcmcxHDAaBgNV\n" +
                    "BAMTE0NBY2VydCBDbGFzcyAzIFJvb3QwHhcNMTgwNDA1MTk0MjQxWhcNMjAwNDA0\n" +
                    "MTk0MjQxWjBbMQswCQYDVQQGEwJBVTEMMAoGA1UECBMDTlNXMQ8wDQYDVQQHEwZT\n" +
                    "eWRuZXkxFDASBgNVBAoTC0NBY2VydCBJbmMuMRcwFQYDVQQDEw53d3cuY2FjZXJ0\n" +
                    "Lm9yZzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANwriThHegmvvYFB\n" +
                    "2X281mJ5d+F2AEEZwaBSSSWoq75BYRJ5l5ke8QHGcx3c8CZDPlPjopyYCIy8LRhA\n" +
                    "75IfVhRnR5imikVG4Gsvp57vAzwrxBtiAh8IqZKSlok30IaZ062G7uPNXaxwNZGY\n" +
                    "c4CcAD2MRmTAxBbVan+wa+h/NTwTa/OfZwjaVdU4mDFJpegGl6tqm10+AdZW7bvP\n" +
                    "Hbg5GPnn8WON0UzR5avrGDkU8013ruFH/Y0G/FlqnAsFAkf20rFYDLRLXzb29Olh\n" +
                    "f6arkF+HOrsnanfyqjwyv5sgvZva3iXmEo0a7NhK2dGM1pO9Pd2AqkvjGARMI0ud\n" +
                    "WrQkDThvoGEV2BvgBqQpF8WYBhlxMr7ToG4y2Dxc+wXgXSy6zPIgZqVwq9OZ4qit\n" +
                    "TeXIiwWQp6nAYlJcPWuDNX2EoTi0FUKn2xCzbDr+i2ZtfZ6NYytxUq+ZwSOZ/o18\n" +
                    "AXnMk82YO95WUFzFbTXrYKF6Sae8caHO92ptjl2tVxLPPRzsIDBMEh2/97fp1jxO\n" +
                    "RjgwWMnBISwznbgIlG9/lY7/DaPHCYlAnIfsqvAasH3SRm5XedmGW4kyOD7D1Cpo\n" +
                    "6vTSk4gs3MyaNvGt9wYATuunqwRjJVX83L/JfrDfxZ8CCb1s+JyYgTPMpbtyvZbN\n" +
                    "1DHYLVfpFL5Nwtx3sZzuMteflQ7NAgMBAAGjggI+MIICOjAMBgNVHRMBAf8EAjAA\n" +
                    "MA4GA1UdDwEB/wQEAwIDqDA0BgNVHSUELTArBggrBgEFBQcDAgYIKwYBBQUHAwEG\n" +
                    "CWCGSAGG+EIEAQYKKwYBBAGCNwoDAzAzBggrBgEFBQcBAQQnMCUwIwYIKwYBBQUH\n" +
                    "MAGGF2h0dHA6Ly9vY3NwLmNhY2VydC5vcmcvMDgGA1UdHwQxMC8wLaAroCmGJ2h0\n" +
                    "dHA6Ly9jcmwuY2FjZXJ0Lm9yZy9jbGFzczMtcmV2b2tlLmNybDCCAXMGA1UdEQSC\n" +
                    "AWowggFmgg53d3cuY2FjZXJ0Lm9yZ6AcBggrBgEFBQcIBaAQDA53d3cuY2FjZXJ0\n" +
                    "Lm9yZ4IRc2VjdXJlLmNhY2VydC5vcmegHwYIKwYBBQUHCAWgEwwRc2VjdXJlLmNh\n" +
                    "Y2VydC5vcmeCEnd3d21haWwuY2FjZXJ0Lm9yZ6AgBggrBgEFBQcIBaAUDBJ3d3dt\n" +
                    "YWlsLmNhY2VydC5vcmeCCmNhY2VydC5vcmegGAYIKwYBBQUHCAWgDAwKY2FjZXJ0\n" +
                    "Lm9yZ4IOd3d3LmNhY2VydC5uZXSgHAYIKwYBBQUHCAWgEAwOd3d3LmNhY2VydC5u\n" +
                    "ZXSCCmNhY2VydC5uZXSgGAYIKwYBBQUHCAWgDAwKY2FjZXJ0Lm5ldIIOd3d3LmNh\n" +
                    "Y2VydC5jb22gHAYIKwYBBQUHCAWgEAwOd3d3LmNhY2VydC5jb22CCmNhY2VydC5j\n" +
                    "b22gGAYIKwYBBQUHCAWgDAwKY2FjZXJ0LmNvbTANBgkqhkiG9w0BAQ0FAAOCAgEA\n" +
                    "pEFsiLHeLxNrP12BIG1QqZja9i1IrBCnWyVvlDmbUMdVHcscAQhWE5sTYkAD+1D7\n" +
                    "VAodoYXo23paZrDKgKoFgZMNLMQ4m93WlCLrInEfENjCxNaPWI5LmsajeZR/5T7C\n" +
                    "5nUqYklCY+3Bc6SBGHXIRDVnGw9AhWgI9f3hSpQhECyokbLwZ17aIGmznTeKx7lV\n" +
                    "DYwaBeyFjZ/AIqovRSkcPTMf1L8LT/SZXuc1urgETbBa+F4tSMGjdGJg2jayojs0\n" +
                    "kD2EFZVGdKYUzOH/rNoQmnTyDEudswp+nim7jgfugztl5KbKeowDFN9KpeineJUW\n" +
                    "lthzARWpWr2gkIH8mGmgvOsIngYGof1sJMJsxcgdrowTrSPW6W/lOWRc6nSGnjg0\n" +
                    "gnshQg3gDN902Kps0OBwbTCrbC4sYu3Xywk0QVxYtcDF2asnsERuSFaZuLWUf2WS\n" +
                    "JYRDGbMuyw6MY+Uoukbee9fJ5Yq77+N0ZeeHRXvRG+PIVyl5KbujznNo6pCGeb3d\n" +
                    "atDvi507zOiRJAWwHTXOEqpJ71ZjuV7XyRTvFe+qb70+t7FiohcZJZhE1hFZrIeV\n" +
                    "iZX2MyJJPaWx2fjx8u/FpaKo01OYNrVOCcnhXzd5jUs+99zxrUVh1CEgC8KIN2zF\n" +
                    "VgnYWDmu4r7D5JbJwxqccicVF9oUa+4HGHvcHdAwfRg=";
    private final Certificate caCertDotOrgRoot
            = CertificateUtils.certificateFromPem(caCertDotOrgRootPem);

    @BeforeClass
    public static void runOnceBeforeClass() {
        // Before API level 20, we need to update the security provider so that TLS 1.2 is enabled
        // in the SSLSocketFactory; otherwise some tests fail because the server requires TLS 1.2
        if (Build.VERSION.SDK_INT < 20) {
            try {
                ProviderInstaller.installIfNeeded(InstrumentationRegistry.getInstrumentation().getContext());
            } catch (GooglePlayServicesRepairableException e) {
                e.printStackTrace();
            } catch (GooglePlayServicesNotAvailableException e) {
                e.printStackTrace();
            }
        }
    }

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        TestableTrustKit.reset();
    }

    //region Tests for when the domain is pinned
    @Test
    public void testPinnedDomainExpiredChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "expired.badssl.com";
        TestableTrustKit.initializeWithNetworkSecurityConfiguration(
                InstrumentationRegistry.getInstrumentation().getContext(), mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection fails
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443).getInputStream();
        } catch (SSLHandshakeException e) {
            if ((e.getCause() instanceof CertificateException
                    && !(e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceiveHandshakeError = true;
            }
        }
        assertTrue(didReceiveHandshakeError);

        if (Build.VERSION.SDK_INT < 17) {
            // TrustKit does not do anything for API level < 17 hence there is no reporting
            return;
        }

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }

    @Test
    public void testPinnedDomainWrongHostnameChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "wrong.host.badssl.com";
        TestableTrustKit.initializeWithNetworkSecurityConfiguration(
                InstrumentationRegistry.getInstrumentation().getContext(), mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection fails
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443).getInputStream();
        } catch (SSLHandshakeException e) {
            if ((e.getCause() instanceof CertificateException
                    && !(e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceiveHandshakeError = true;
            }
        }
        assertTrue(didReceiveHandshakeError);

        if (Build.VERSION.SDK_INT < 17) {
            // TrustKit does not do anything for API level < 17 hence there is no reporting
            return;
        }

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }

    @Test
    public void testPinnedDomainSuccessAnchor() throws IOException {
        String serverHostname = "www.datatheorem.com";
        TestableTrustKit.initializeWithNetworkSecurityConfiguration(
                InstrumentationRegistry.getInstrumentation().getContext(), mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection succeeds
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        Socket socket = test.createSocket(serverHostname, 443);
        socket.getInputStream();

        assertTrue(socket.isConnected());
        socket.close();

        // Ensure the background reporter was NOT called
        verify(mockReporter, never()).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED)
        );
    }

    @Test
    public void testPinnedDomainSuccessLeaf() throws IOException {
        String serverHostname = "datatheorem.com";
        TestableTrustKit.initializeWithNetworkSecurityConfiguration(
                InstrumentationRegistry.getInstrumentation().getContext(), mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection succeeds
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        Socket socket = test.createSocket(serverHostname, 443);
        socket.getInputStream();

        assertTrue(socket.isConnected());
        socket.close();

        // Ensure the background reporter was NOT called
        verify(mockReporter, never()).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED)
        );
    }

    @Test
    public void testPinnedDomainInvalidPin() throws IOException {
        if (Build.VERSION.SDK_INT < 17) {
            // TrustKit does not do anything for API level < 17 hence the connection will succeed
            return;
        }

        String serverHostname = "www.yahoo.com";
        TestableTrustKit.initializeWithNetworkSecurityConfiguration(
                InstrumentationRegistry.getInstrumentation().getContext(), mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection fails
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        boolean didReceivePinningError = false;
        try {
            test.createSocket(serverHostname, 443).getInputStream();
        } catch (SSLHandshakeException e) {
            if ((e.getCause() instanceof CertificateException
                    && (e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceivePinningError = true;
            }
        }
        assertTrue(didReceivePinningError);

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED)
        );
    }

    @Test
    public void testPinnedDomainInvalidPinAndPinningNotEnforced() throws IOException {
        String serverHostname = "www.github.com";
        TestableTrustKit.initializeWithNetworkSecurityConfiguration(
                InstrumentationRegistry.getInstrumentation().getContext(), mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection succeeds
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        Socket socket = test.createSocket(serverHostname, 443);
        socket.getInputStream();

        assertTrue(socket.isConnected());
        socket.close();

        if (Build.VERSION.SDK_INT < 17) {
            // TrustKit does not do anything for API level < 17 hence there is no reporting
            return;
        }

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED)
        );
    }

    @Test
    public void testPinnedDomainInvalidPinAndPolicyExpired() throws IOException {
        String serverHostname = "www.microsoft.com";
        TestableTrustKit.initializeWithNetworkSecurityConfiguration(
                InstrumentationRegistry.getInstrumentation().getContext(), mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection succeeds
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        Socket socket = test.createSocket(serverHostname, 443);
        socket.getInputStream();

        assertTrue(socket.isConnected());
        socket.close();

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
    public void testPinnedDomainUntrustedChainAndPinningNotEnforced() throws IOException {
        String serverHostname = "untrusted-root.badssl.com";
        TestableTrustKit.initializeWithNetworkSecurityConfiguration(
                InstrumentationRegistry.getInstrumentation().getContext(), mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection fails
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443).getInputStream();
        } catch (SSLHandshakeException e) {
            if ((e.getCause() instanceof CertificateException
                    && !(e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceiveHandshakeError = true;
            }
        }

        // Ensure the SSL handshake failed (but not because of a pinning error)
        assertTrue(didReceiveHandshakeError);

        if (Build.VERSION.SDK_INT < 17) {
            // TrustKit does not do anything for API level < 17 hence there is no reporting
            return;
        }

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }

    @Test
    public void testDebugOverridesInvalidPinButOverridePins() throws IOException, CertificateException {
        if (Build.VERSION.SDK_INT >= 24) {
            // This test will not work when using the Android N XML network policy because we can't
            // dynamically remove the debug-overrides tag defined in the XML policy which adds the
            // cacert.org CA cert as a trusted CA
            return;
        }
        if (Build.VERSION.SDK_INT < 17) {
            // TrustKit does not do anything for API level < 17 hence the connection will succeed
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
        // overridePins to true
        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                true,
                new HashSet<Certificate>(){{ add(caCertDotOrgRoot); }},
                InstrumentationRegistry.getInstrumentation().getContext(),
                mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection succeeds
        // This means that debug-overrides properly enables the supplied debug CA cert and
        // disables pinning when overridePins is true
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        Socket socket = test.createSocket(serverHostname, 443);
        socket.getInputStream();

        assertTrue(socket.isConnected());
        socket.close();

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
        if (Build.VERSION.SDK_INT < 17) {
            // TrustKit does not do anything for API level < 17 hence the connection will succeed
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
        Context mockContext = InstrumentationRegistry.getInstrumentation().getContext();
        int originalAppFlags = mockContext.getApplicationInfo().flags;
        mockContext.getApplicationInfo().flags = 0;
        TestableTrustKit.init(new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                true,
                new HashSet<Certificate>(){{ add(caCertDotOrgRoot); }},
                mockContext,
                mockReporter);
        mockContext.getApplicationInfo().flags = originalAppFlags;

        // Create a TrustKit SocketFactory and ensure the connection fails
        // This means that debug-overrides property was ignored because the App is not debuggable
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443).getInputStream();
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
                eq(TestableTrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname)),
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
        if (Build.VERSION.SDK_INT < 17) {
            // TrustKit does not do anything for API level < 17 hence the connection will succeed
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
                InstrumentationRegistry.getInstrumentation().getContext(),
                mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection fails
        // This means that debug-overrides properly enables the supplied debug CA cert but does not
        // disable pinning when overridePins is false
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        boolean didReceivePinningError = false;
        try {
            test.createSocket(serverHostname, 443).getInputStream();
        } catch (SSLHandshakeException e) {
            if ((e.getCause() instanceof CertificateException
                    && (e.getCause().getMessage().startsWith("Pin verification failed")))) {
                didReceivePinningError = true;
            }
        }
        assertTrue(didReceivePinningError);

        // Ensure the background reporter was called
        verify(mockReporter).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED)
        );
    }
    //endregion

    //region Tests for when the domain is NOT pinned
    @Test
    public void testNonPinnedDomainUntrustedRootChain() throws IOException {
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
                InstrumentationRegistry.getInstrumentation().getContext(),
                mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection fails
        // This means that TrustKit does not interfere with default certificate validation
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443).getInputStream();
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
                eq(TestableTrustKit.getInstance().getConfiguration().getPolicyForHostname(serverHostname)),
                eq(PinningValidationResult.FAILED)
        );
    }

    @Test
    public void testNonPinnedDomainSuccess() throws IOException {
        // Initialize TrustKit
        String serverHostname = "www.google.com";
        TestableTrustKit.initializeWithNetworkSecurityConfiguration(
                InstrumentationRegistry.getInstrumentation().getContext(), mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection succeeds
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        Socket socket = test.createSocket(serverHostname, 443);
        socket.getInputStream();

        assertTrue(socket.isConnected());
        socket.close();

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
        if (Build.VERSION.SDK_INT >= 24) {
            // This test will not work when using the Android N XML network policy because we can't
            // dynamically add/remove a debug-override tag defined in the XML policy which adds the
            // cacert.org CA cert as a trusted CA
            return;
        }
        if (Build.VERSION.SDK_INT < 17) {
            // TrustKit does not do anything for API level < 17 hence the connection will succeed
            return;
        }

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
                InstrumentationRegistry.getInstrumentation().getContext(),
                mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection succeeds
        // This means that debug-overrides properly enables the supplied debug CA cert
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        Socket socket = test.createSocket(serverHostname, 443);
        socket.getInputStream();

        assertTrue(socket.isConnected());
        socket.close();

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
        if (Build.VERSION.SDK_INT >= 24) {
            // This test will not work when using the Android N XML network policy because we can't
            // dynamically add/remove a debug-override tag defined in the XML policy which adds the
            // cacert.org CA cert as a trusted CA
            return;
        }

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
                InstrumentationRegistry.getInstrumentation().getContext(),
                mockReporter);

        // Create a TrustKit SocketFactory and ensure the connection succeeds
        // This means that debug-overrides does not disable the System CAs
        SSLSocketFactory test = TestableTrustKit.getInstance().getSSLSocketFactory(serverHostname);
        Socket socket = test.createSocket(serverHostname, 443);
        socket.getInputStream();

        assertTrue(socket.isConnected());
        socket.close();

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
