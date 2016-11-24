package com.datatheorem.android.trustkit;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.NetworkSecurityPolicy;
import android.support.annotation.NonNull;

import com.datatheorem.android.trustkit.config.ConfigurationException;
import com.datatheorem.android.trustkit.config.TrustKitConfiguration;
import com.datatheorem.android.trustkit.pinning.TrustKitSSLSocketFactory;
import com.datatheorem.android.trustkit.pinning.TrustManagerBuilder;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;
import com.datatheorem.android.trustkit.utils.TrustKitLog;
import com.datatheorem.android.trustkit.utils.VendorIdentifier;

import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Set;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;


/**
 * Class that provides all of the TrustKit public APIs.
 *
 * <p>
 *     It should be used to initialize the App's SSL pinning policy and to retrieve the
 *     corresponding {@code SSLSocketFactory} and {@code X509TrustManager}, to be used to add SSL
 *     pinning validation to the App's network connections.
 * </p>
 *
 * <p>
 *     TrustKit works by extending the
 *     <a href="https://developer.android.com/training/articles/security-config.html">Android N
 *     Network Security Configuration</a> in two ways:
 *
 *     <ul>
 *         <li>It provides support for the SSL pinning functionality of the Android N Network
 *             Security Configuration to earlier versions of Android, down to API level 17. This
 *             allows Apps supporting versions of Android that earlier than N to implement SSL
 *             pinning in a way that is future-proof.</li>
 *
 *         <li>It adds the ability to send reports when pinning validation failed for a specific
 *             connection. Reports have a format that is similar to the report-uri feature of
 *             <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning">HTTP
 *             Public Key Pinning</a> and <a href="https://github.com/datatheorem/trustkit">TrustKit
 *             iOS</a>.</li>
 *     </ul>
 * </p>
 *
 * <h3>Supported Android N Network Security Settings</h3>
 *
 * <p>
 *     On devices before Android N, TrustKit supports the following XML tags defined in the
 *     <a href="https://developer.android.com/training/articles/security-config.html#CertificatePinning">
 *         Android N Network Security Configuration</a> for deploying SSL pinning:
 * </p>
 *
 * <ul>
 *     <li>{@code <domain-config>}.</li>
 *     <li>{@code <domain>} and the {@code includeSubdomains} attribute.</li>
 *     <li>{@code <pin-set>} and the {@code expiration} attribute.</li>
 *     <li>{@code <pin>} and the {@code digest} attribute.</li>
 *     <li>{@code <debug-overrides>}.</li>
 *     <li>{@code <trust-anchors>}, but only within a {@code <debug-overrides>} tag. Hence, custom
 *     trust anchors for specific domains cannot be set.</li>
 *     <li>{@code <certificates>} and the {@code overridePins} and {@code src} attributes. Only raw
 *     certificate files are supported for the {@code src} attribute ({@code user} and
 *     {@code system} values will be ignored).</li>
 * </ul>
 *
 *<p>
 *     On Android N devices, the OS' implementation is used and all XML tags are supported.
 *</p>
 *
 * <h3>Additional TrustKit Settings</h3>
 *
 * <p>
 *     TrustKit provides additional functionality to not enforce pinning validation and to allow
 *     reports to be sent by the App whenever a pinning validation failure occurred.
 * </p>
 *
 * <h4>{@code <trustkit-config>}</h4>
 *
 * <p>
 *     The main tag for specifying additional TrustKit settings, to be defined within a
 *     {@code <domain-config>} entry. It supports the following attributes:
 * </p>
 *
 *     <ul>
 *         <li>{@code enforcePinning}: if set to {@code false}, TrustKit will not block SSL
 *         connections that caused a pinning validation error; default value is {@code false}. When
 *         a pinning failure occurs, pin failure reports will always be sent to the configured
 *         report URIs regardless of the value of {@code enforcePinning}. This behavior allows
 *         deploying pinning validation without the risk of locking out users due to a
 *         misconfiguration, while still receiving reports in order to assess how many users would
 *         be affected by pinning.</li>
 *
 *         <li>{@code disableDefaultReportUri}: if set to {@code true}, the default report URL for
 *         sending pin failure reports will be disabled; default value is {@code false}. By default,
 *         pin failure reports are sent to a report server hosted by Data Theorem, for detecting
 *         potential CA compromises and man-in-the-middle attacks, as well as providing a free
 *         dashboard for developers; email
 *         <a href="mailto:info@datatheorem.com">info@datatheorem.com</a> if you'd like a dashboard
 *         for your App. Only pin failure reports are sent, which contain the App's package name,
 *         a randomly-generated ID, and the server's hostname and certificate chain that failed
 *         validation.</li>
 *     </ul>
 *
 * <h4>{@code <report-uri>}</h4>
 *
 *     A URL to which pin validation failures should be reported, to be defined within a
 *     {@code <trustkit-config>} tag. The format of the reports is similar to the one described in
 *     RFC 7469 for the HPKP specification:
 *     <pre>
 *     <code>
 *     {
 *     "app-bundle-id":"com.example.ABC",
 *     "app-version":"1.0",
 *     "app-vendor-id":"599F9C00-92DC-4B5C-9464-7971F01F8370",
 *     "date-time": "2015-07-10T20:03:14Z",
 *     "hostname": "mail.example.com",
 *     "port": 0,
 *     "include-subdomains": true,
 *     "noted-hostname": "example.com",
 *     "validated-certificate-chain": [
 *     pem1, ... pemN
 *     ],
 *     "known-pins": [
 *     "pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"",
 *     "pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\""
 *     ],
 *     "validation-result":1
 *     }
 *     </code>
 *     </pre>
 *
 * <h3>Sample TrustKit Configuration</h3>
 * <p>
 *     The following configuration will pin the www.datatheorem.com domain without enforcing pinning
 *     validation, and will send pinning failure reports to report.datatheorem.com. It also defines
 *     a debug overrides to add a debug certificate authority to the App's trust store for easier
 *     debugging of the App's network traffic.
 * </p>
 * <pre>
 *     {@code
 *         <!-- res/xml/network_security_config.xml -->
 *         <?xml version="1.0" encoding="utf-8"?>
 *         <network-security-config>
 *         <!-- Pin the domain www.datatheorem.com -->
 *         <!-- Official Android N API -->
 *         <domain-config>
 *         <domain>www.datatheorem.com</domain>
 *         <pin-set>
 *         <pin digest="SHA-256">k3XnEYQCK79AtL9GYnT/nyhsabas03V+bhRQYHQbpXU=</pin>
 *         <pin digest="SHA-256">2kOi4HdYYsvTR1sTIR7RHwlf2SescTrpza9ZrWy7poQ=</pin>
 *         </pin-set>
 *         <!-- TrustKit Android API -->
 *         <!-- Do not enforce pinning validation -->
 *         <trustkit-config enforcePinning="false">
 *         <!-- Add a reporting URL for pin validation reports -->
 *         <report-uri>http://report.datatheorem.com/log_report</report-uri>
 *         </trustkit-config>
 *         </domain-config>
 *         <debug-overrides>
 *         <trust-anchors>
 *         <!-- For debugging purposes, add a debug CA and override pins -->
 *         <certificates overridePins="true" src="@raw/debugca" />
 *         </trust-anchors>
 *         <debug-overrides>
 *         </network-security-config>
 *     }
 * </pre>
 *
 */
public class TrustKit {

    protected static TrustKit trustKitInstance;

    private final TrustKitConfiguration trustKitConfiguration;

    protected TrustKit(@NonNull Context context,
                       @NonNull TrustKitConfiguration trustKitConfiguration) {
        this.trustKitConfiguration = trustKitConfiguration;

        // Setup the debug-overrides setting if the App is debuggable
        // Do not use BuildConfig.DEBUG as it does not work for libraries
        boolean isAppDebuggable = (0 !=
                (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE));
        Set<Certificate> debugCaCerts = null;
        boolean shouldOverridePins = false;
        if (isAppDebuggable) {
            debugCaCerts = trustKitConfiguration.getDebugCaCertificates();
            if (debugCaCerts != null) {
                TrustKitLog.i("App is debuggable - processing <debug-overrides> configuration.");
            }
            shouldOverridePins = trustKitConfiguration.shouldOverridePins();
        }

        // Create the background reporter for sending pin failure reports
        String appPackageName = context.getPackageName();
        String appVersion;
        try {
            appVersion = context.getPackageManager().getPackageInfo(appPackageName, 0).versionName;

        } catch (PackageManager.NameNotFoundException e) {
            appVersion = "N/A";
        }

        if (appVersion == null) {
            appVersion = "N/A";
        }

        String appVendorId = VendorIdentifier.getOrCreate(context);
        BackgroundReporter reporter = new BackgroundReporter(appPackageName, appVersion,
                appVendorId);

        // Initialize the trust manager builder
        try {
            TrustManagerBuilder.initializeBaselineTrustManager(debugCaCerts,
                    shouldOverridePins, reporter);
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException
                | IOException e) {
            throw new ConfigurationException("Could not parse <debug-overrides> certificates");
        }
    }

    /** Initialize TrustKit with the Network Security Configuration file at the default location
     * res/xml/network_security_config.xml.
     *
     * @param context the application's context.
     * @throws ConfigurationException if the policy could not be parsed or contained errors.
     */
    @NonNull
    public synchronized static TrustKit initializeWithNetworkSecurityConfiguration(
            @NonNull Context context) {
        // Try to get the default network policy resource ID
        int networkSecurityConfigId = context.getResources().getIdentifier(
                "network_security_config", "xml", context.getPackageName());
        return initializeWithNetworkSecurityConfiguration(context, networkSecurityConfigId);
    }

    /** Initialize TrustKit with the Network Security Configuration file with the specified
     * resource ID.
     *
     * @param context the application's context.
     * @param configurationResourceId the resource ID for the Network Security Configuration file to
     *                                use.
     * @throws ConfigurationException if the policy could not be parsed or contained errors.
     */
    @NonNull
    public synchronized static TrustKit initializeWithNetworkSecurityConfiguration(
            @NonNull Context context, int configurationResourceId) {
        if (trustKitInstance != null) {
            throw new IllegalStateException("TrustKit has already been initialized");
        }

        // On Android N, ensure that the system was also able to load the policy
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M &&
                NetworkSecurityPolicy.getInstance() == null) {
            // Android did not find a policy because the supplied resource ID is wrong or the policy
            // file is not properly setup in the manifest, or contains bad data
            throw new ConfigurationException("TrustKit was initialized with a network policy that" +
                    "was not properly configured for Android N ");
        }

        // Then try to load the supplied policy
        TrustKitConfiguration trustKitConfiguration;
        try {
            trustKitConfiguration = TrustKitConfiguration.fromXmlPolicy(
                    context, context.getResources().getXml(configurationResourceId)
            );
        } catch (XmlPullParserException | IOException e) {
            throw new ConfigurationException("Could not parse network security policy file");
        } catch (CertificateException e) {
            throw new ConfigurationException("Could not find the debug certificate in the " +
                    "network security police file");
        }

        trustKitInstance = new TrustKit(context, trustKitConfiguration);
        return trustKitInstance;
    }

    /** Retrieve the initialized instance of TrustKit.
     *
     * @throws IllegalStateException if TrustKit has not been initialized.
     */
    @NonNull
    public static TrustKit getInstance() {
        if (trustKitInstance == null) {
            throw new IllegalStateException("TrustKit has not been initialized");
        }
        return trustKitInstance;
    }

    /** Retrieve the current TrustKit configuration.
     *
     */
    @NonNull
    public TrustKitConfiguration getConfiguration() { return trustKitConfiguration; }

    /** Retrieve an {@code SSLSSocketFactory} that implements SSL pinning validation based on the
     * current TrustKit configuration. It can be used with most network APIs (such as
     * {@code HttpsUrlConnection}) to add SSL pinning validation to the connections.
     *
     * <p>
     *     The {@code SSLSocketFactory} is configured for the specific domain the socket will
     *     connect to first, and will keep this domain's pinning policy even if there is a
     *     redirection to a different domain during the connection. Hence validation will always
     *     fail in the case of a redirection to a different domain.
     *     Pinning validation is only meant to be used on the App's API server(s), and redirections
     *     to other domains should not happen in this use case.
     * </p>
     */
    @NonNull
    public SSLSocketFactory getSSLSocketFactory() {
        return new TrustKitSSLSocketFactory();
    }

    /** Retrieve an {@code X509TrustManager} that implements SSL pinning validation based on the
     * current TrustKit configuration for the supplied hostname. It can be used with some network
     * APIs that let developers supply a trust manager to customize SSL validation.
     *
     * <p>
     *     The {@code X509TrustManager} is configured for the supplied hostname, and will keep this
     *     domain's pinning policy even if there is a redirection to a different domain during the
     *     connection. Hence validation will always fail in the case of a redirection to a different
     *     domain.
     *     Pinning validation is only meant to be used on the App's API server(s), and redirections
     *     to other domains should not happen in this use case.
     * </p>
     *
     * @param serverHostname the server's hostname that the {@code X509TrustManager} will be used to
     *                       connect to. This hostname will be used to retrieve the pinning policy
     *                       from the current TrustKit configuration.
     */
    @NonNull
    public X509TrustManager getTrustManager(@NonNull String serverHostname) {
        return TrustManagerBuilder.getTrustManager(serverHostname);
    }
}
