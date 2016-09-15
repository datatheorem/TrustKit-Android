package com.datatheorem.android.trustkit.pinning;

import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.datatheorem.android.trustkit.DebugTrustKit;
import com.datatheorem.android.trustkit.PinValidationResult;
import com.datatheorem.android.trustkit.config.PinnedDomainConfiguration;
import com.datatheorem.android.trustkit.config.TrustKitConfiguration;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;

import static junit.framework.Assert.assertTrue;
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
        DebugTrustKit.resetConfiguration();
    }

    // TODO(ad): Test all three socket methods

    //region Utility methods
    // To use when we don't care about the pins configured for the domain
    private void initializeTrustKitWithBadPins(String serverHostname, boolean enforcePinning) {
        TrustKitConfiguration trustKitConfig = new TrustKitConfiguration();
        PinnedDomainConfiguration datatheoremConfig = new PinnedDomainConfiguration.Builder()
                .publicKeyHashes(new String[]{
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Bad pin
                })
                .enforcePinning(enforcePinning)
                .build();
        trustKitConfig.put(serverHostname, datatheoremConfig);
        DebugTrustKit.init(InstrumentationRegistry.getContext(), trustKitConfig, mockReporter);
    }
    //endregion

    //region Tests for when the domain is NOT pinned
    @Test
    public void testPinnedDomainExpiredChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "expired.badssl.com";
        initializeTrustKitWithBadPins(serverHostname, true);

        // Create an PinningSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new PinningSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if (e.getCause() instanceof CertificateException) {
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
                eq(serverHostname),
                eq(DebugTrustKit.getInstance().getConfiguration().get(serverHostname)),
                eq(PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }

    @Test
    public void testPinnedDomainWrongHostnameChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "wrong.host.badssl.com";
        initializeTrustKitWithBadPins(serverHostname, true);

        // Create an PinningSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new PinningSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if (e.getCause() instanceof CertificateException) {
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
                eq(serverHostname),
                eq(DebugTrustKit.getInstance().getConfiguration().get(serverHostname)),
                eq(PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }

    @Test
    public void testPinnedDomainUntrustedRootChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "untrusted-root.badssl.com";
        initializeTrustKitWithBadPins(serverHostname, true);

        // Create an PinningSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new PinningSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if (e.getCause() instanceof CertificateException) {
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
                eq(serverHostname),
                eq(DebugTrustKit.getInstance().getConfiguration().get(serverHostname)),
                eq(PinValidationResult.FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED)
        );
    }

    @Test
    public void testPinnedDomainSuccess() throws IOException {
        // Initialize TrustKit
        String serverHostname = "www.datatheorem.com";
        TrustKitConfiguration trustKitConfig = new TrustKitConfiguration();
        PinnedDomainConfiguration datatheoremConfig = new PinnedDomainConfiguration.Builder()
                .publicKeyHashes(new String[]{
                        "grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=" // CA pin
                })
                .enforcePinning(false)
                .build();
        trustKitConfig.put(serverHostname, datatheoremConfig);
        DebugTrustKit.init(InstrumentationRegistry.getContext(), trustKitConfig, mockReporter);

        // Create an PinningSSLSocketFactory and ensure connection succeeds
        SSLSocketFactory test = new PinningSSLSocketFactory();
        test.createSocket(serverHostname, 443);

        // Ensure the background reporter was NOT called
        verify(mockReporter, never()).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(serverHostname),
                eq(DebugTrustKit.getInstance().getConfiguration().get(serverHostname)),
                eq(PinValidationResult.FAILED)
        );
    }

    @Test
    public void testPinnedDomainInvalidPin() throws IOException {
        // Initialize TrustKit
        String serverHostname = "www.yahoo.com";
        initializeTrustKitWithBadPins(serverHostname, true);

        // Create an PinningSSLSocketFactory and ensure connection succeeds
        SSLSocketFactory test = new PinningSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if (e.getCause() instanceof CertificateException) {
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
                eq(serverHostname),
                eq(DebugTrustKit.getInstance().getConfiguration().get(serverHostname)),
                eq(PinValidationResult.FAILED)
        );
    }
    //endregion

    //region Tests for when the domain is NOT pinned
    @Test
    public void testNonPinnedDomainExpiredChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "expired.badssl.com";
        initializeTrustKitWithBadPins("www.someotherdomain.com", true);

        // Create an PinningSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new PinningSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if (e.getCause() instanceof CertificateException) {
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
                eq(serverHostname),
                eq(DebugTrustKit.getInstance().getConfiguration().get(serverHostname)),
                eq(PinValidationResult.FAILED)
        );
    }

    @Test
    public void testNonPinnedDomainWrongHostnameChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "wrong.host.badssl.com";
        initializeTrustKitWithBadPins("www.someotherdomain.com", true);

        // Create an PinningSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new PinningSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLPeerUnverifiedException e) {
            didReceiveHandshakeError = true;
        }

        assertTrue(didReceiveHandshakeError);

        // Ensure the background reporter was NOT called as we only want reports for pinned domains
        verify(mockReporter, never()).pinValidationFailed(
                eq(serverHostname),
                eq(0),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                (List<X509Certificate>) org.mockito.Matchers.isNotNull(),
                eq(serverHostname),
                eq(DebugTrustKit.getInstance().getConfiguration().get(serverHostname)),
                eq(PinValidationResult.FAILED)
        );
    }

    @Test
    public void testNonPinnedDomainUntrustedRootChain() throws IOException {
        // Initialize TrustKit
        String serverHostname = "untrusted-root.badssl.com";
        initializeTrustKitWithBadPins("www.someotherdomain.com", true);

        // Create an PinningSSLSocketFactory and ensure connection fails
        SSLSocketFactory test = new PinningSSLSocketFactory();
        boolean didReceiveHandshakeError = false;
        try {
            test.createSocket(serverHostname, 443);
        } catch (SSLHandshakeException e) {
            if (e.getCause() instanceof CertificateException) {
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
                eq(serverHostname),
                eq(DebugTrustKit.getInstance().getConfiguration().get(serverHostname)),
                eq(PinValidationResult.FAILED)
        );
    }

    @Test
    public void testNonPinnedDomainSuccess() throws IOException {
        // Initialize TrustKit
        String serverHostname = "www.datatheorem.com";
        initializeTrustKitWithBadPins("www.someotherdomain.com", true);

        // Create an PinningSSLSocketFactory and ensure connection succeeds
        SSLSocketFactory test = new PinningSSLSocketFactory();
        test.createSocket(serverHostname, 443);

        // Ensure the background reporter was NOT called
        verify(mockReporter, never()).pinValidationFailed(
                anyString(),
                anyInt(),
                (List<X509Certificate>) any(),
                (List<X509Certificate>) any(),
                anyString(),
                any(PinnedDomainConfiguration.class),
                any(PinValidationResult.class)
        );
    }
    //endregion
}
