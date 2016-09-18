package com.datatheorem.android.trustkit.pinning;

import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.datatheorem.android.trustkit.TestableTrustKit;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
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


@RunWith(AndroidJUnit4.class)
public class PinningSSLSocketFactoryTest {

    @Mock
    private BackgroundReporter mockReporter;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        TestableTrustKit.initWithNetworkPolicy(InstrumentationRegistry.getContext(), mockReporter);
    }

    @After
    public void tearDown() {
        TestableTrustKit.resetConfiguration();
    }

    //region Tests for when the domain is NOT pinned
    @Test
    public void testPinnedDomainExpiredChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "expired.badssl.com";

        // Create an PinningSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new PinningSSLSocketFactory();
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
                eq(TestableTrustKit.getInstance().getConfiguration().getByPinnedHostname(serverHostname)),
                eq(PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }

    @Test
    public void testPinnedDomainWrongHostnameChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "wrong.host.badssl.com";

        // Create an PinningSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new PinningSSLSocketFactory();
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
                eq(TestableTrustKit.getInstance().getConfiguration().getByPinnedHostname(serverHostname)),
                eq(PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }


    @Test
    public void testPinnedDomainSuccess() throws IOException {
        String serverHostname = "www.datatheorem.com";

        // Create an PinningSSLSocketFactory and ensure connection succeeds
        SSLSocketFactory test = new PinningSSLSocketFactory();
        test.createSocket(serverHostname, 443);

        // Ensure the background reporter was NOT called
        verify(mockReporter, never()).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(TestableTrustKit.getInstance().getConfiguration().getByPinnedHostname(serverHostname)),
                eq(PinValidationResult.FAILED)
        );
    }

    @Test
    public void testPinnedDomainInvalidPin() throws IOException {
        String serverHostname = "www.yahoo.com";

        // Create an PinningSSLSocketFactory and ensure connection succeeds
        SSLSocketFactory test = new PinningSSLSocketFactory();
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
                eq(TestableTrustKit.getInstance().getConfiguration().getByPinnedHostname(serverHostname)),
                eq(PinValidationResult.FAILED)
        );
    }

    @Test
    public void testPinnedDomainInvalidPinAndPinningNotEnforced() throws IOException {
        String serverHostname = "www.github.com";

        // Create an PinningSSLSocketFactory and ensure connection succeeds
        SSLSocketFactory test = new PinningSSLSocketFactory();
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
                eq(TestableTrustKit.getInstance().getConfiguration().getByPinnedHostname(serverHostname)),
                eq(PinValidationResult.FAILED)
        );
    }

    @Test
    public void testPinnedDomainUntrustedChainAndPinningNotEnforced() throws IOException {
        String serverHostname = "untrusted-root.badssl.com";

        // Create an PinningSSLSocketFactory and ensure connection succeeds
        SSLSocketFactory test = new PinningSSLSocketFactory();
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
                eq(TestableTrustKit.getInstance().getConfiguration().getByPinnedHostname(serverHostname)),
                eq(PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }
    //endregion

    //region Tests for when the domain is NOT pinned
    @Test
    public void testNonPinnedDomainUntrustedRootChain() throws IOException {
        String serverHostname = "www.cacert.org";

        // Create an PinningSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new PinningSSLSocketFactory();
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
                eq(TestableTrustKit.getInstance().getConfiguration().getByPinnedHostname(serverHostname)),
                eq(PinValidationResult.FAILED)
        );
    }

    @Test
    public void testNonPinnedDomainSuccess() throws IOException {
        // Initialize TrustKit
        String serverHostname = "www.google.com";

        // Create an PinningSSLSocketFactory and ensure connection succeeds
        SSLSocketFactory test = new PinningSSLSocketFactory();
        test.createSocket(serverHostname, 443);

        // Ensure the background reporter was NOT called
        verify(mockReporter, never()).pinValidationFailed(
                anyString(),
                anyInt(),
                (List<X509Certificate>) any(),
                (List<X509Certificate>) any(),
                any(PinnedDomainConfiguration.class),
                any(PinValidationResult.class)
        );
    }
    //endregion
}
