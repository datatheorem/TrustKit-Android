package com.datatheorem.android.trustkit.pinning;

import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

// TODO(ad): Teat debug overrides
@RunWith(AndroidJUnit4.class)
public class PinningSSLSocketFactoryTest {

    @Mock
    private BackgroundReporter mockReporter;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @After
    public void tearDown() {
        TestableTrustKit.reset();
        TestableTrustManagerBuilder.reset();
    }

    //region Tests for when the domain is NOT pinned
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

        TestableTrustKit.init(InstrumentationRegistry.getContext(),
                new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
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

        TestableTrustKit.init(InstrumentationRegistry.getContext(),
                new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
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

        TestableTrustKit.init(InstrumentationRegistry.getContext(),
                new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
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

        TestableTrustKit.init(InstrumentationRegistry.getContext(),
                new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection succeeds
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

        TestableTrustKit.init(InstrumentationRegistry.getContext(),
                new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection succeeds
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

        // Handshake was successful
        assertFalse(didReceiveHandshakeError);

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

        TestableTrustKit.init(InstrumentationRegistry.getContext(),
                new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
                mockReporter);

        // Create an TrustKitSSLSocketFactory and ensure connection succeeds
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

        TestableTrustKit.init(InstrumentationRegistry.getContext(),
                new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
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

        TestableTrustKit.init(InstrumentationRegistry.getContext(),
                new HashSet<DomainPinningPolicy>() {{ add(domainPolicy); }},
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
    //endregion
}
