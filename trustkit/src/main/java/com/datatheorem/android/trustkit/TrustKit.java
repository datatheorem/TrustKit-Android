package com.datatheorem.android.trustkit;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.annotation.NonNull;
import android.util.Printer;

import com.datatheorem.android.trustkit.config.ConfigurationException;
import com.datatheorem.android.trustkit.config.TrustKitConfiguration;
import com.datatheorem.android.trustkit.pinning.TrustManagerBuilder;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;
import com.datatheorem.android.trustkit.utils.TrustKitLog;
import com.datatheorem.android.trustkit.utils.VendorIdentifier;

import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
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
 *     <a href="https://developer.android.com/training/articles/security-config.html" target="_blank">
 *         Android N Network Security Configuration</a> in two ways:
 *
 *     <ul>
 *         <li>It provides support for the SSL pinning functionality of the Android N Network
 *             Security Configuration to earlier versions of Android, down to API level 17. This
 *             allows Apps supporting versions of Android that earlier than N to implement SSL
 *             pinning in a way that is future-proof.</li>
 *
 *         <li>It adds the ability to send reports when pinning validation failed for a specific
 *             connection. Reports have a format that is similar to the report-uri feature of
 *             <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning" target="_blank">HTTP
 *             Public Key Pinning</a> and <a href="https://github.com/datatheorem/trustkit" target="_blank">TrustKit
 *             iOS</a>.</li>
 *     </ul>
 *
 *     For better compatibility, TrustKit will also run on API levels 15 and 16 but its
 *     functionality will be disabled.
 * </p>
 *
 * <h3>Supported Android N Network Security Settings</h3>
 *
 * <p>
 *     On devices before Android N, TrustKit supports the following XML tags defined in the
 *     <a href="https://developer.android.com/training/articles/security-config.html#CertificatePinning" target="_blank">
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
 *     <a href="https://tools.ietf.org/html/rfc7469#section-2.1.4" target="_blank">RFC 7469 for the HPKP
 *     specification</a>. A sample TrustKit report is available
 *     <a href="https://github.com/datatheorem/TrustKit-Android/blob/master/docs/sample_report.json" target="_blank">
 *         in the project's repository
 *     </a>.
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
 *         </debug-overrides>
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
        BackgroundReporter reporter = new BackgroundReporter(context, appPackageName, appVersion,
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

    /** Try to retrieve the Network Security Policy resource ID configured in the App's manifest.
     * Somewhat convoluted as other means of getting the resource ID involve using private APIs.
     *
     * @param context android context
     * @return The resource ID for the XML file containing the configured Network Security Policy or
     * -1 if no policy was configured in the App's manifest or if we are not running on Android N.
     */
    static private int getNetSecConfigResourceId(@NonNull Context context) {
        ApplicationInfo info = context.getApplicationInfo();

        // Dump the content of the ApplicationInfo, which contains the resource ID on Android N
        class NetSecConfigResIdRetriever implements Printer {
            private int netSecConfigResourceId = -1;

            public void println(String x) {
                if (netSecConfigResourceId == -1) {
                    // Attempt at parsing "networkSecurityConfigRes=0x1234"
                    String NETSEC_LINE_FORMAT = "networkSecurityConfigRes=0x";
                    if (x.contains(NETSEC_LINE_FORMAT)) {
                        netSecConfigResourceId =
                                Integer.parseInt(x.substring(NETSEC_LINE_FORMAT.length()), 16);
                    }
                }
            }

            private int getNetworkSecurityConfigResId() { return netSecConfigResourceId; }
        }

        NetSecConfigResIdRetriever retriever = new NetSecConfigResIdRetriever();
        info.dump(retriever, "");
        return retriever.getNetworkSecurityConfigResId();
    }

    /** Initialize TrustKit with the Network Security Configuration file at the default location
     * res/xml/network_security_config.xml. The Network Security Configuration file must also have
     * been <a href="https://developer.android.com/training/articles/security-config.html#manifest" target="_blank">
     *     added to the App's manifest</a>.
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
     * resource ID. The Network Security Configuration file must also have
     * been <a href="https://developer.android.com/training/articles/security-config.html#manifest" target="_blank">
     *     added to the App's manifest</a>.
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            // This will need to be updated/double-checked for subsequent versions of Android
            int systemConfigResId = getNetSecConfigResourceId(context);
            if (systemConfigResId == -1) {
                // Android did not find a policy because the supplied resource ID is wrong or the
                // policy file is not properly setup in the manifest, or contains bad data
                throw new ConfigurationException("TrustKit was initialized with a network policy " +
                        "that was not properly configured for Android N - make sure it is in the " +
                        "App's Manifest.");
            }
            else if (systemConfigResId != configurationResourceId) {
                throw new ConfigurationException("TrustKit was initialized with a different " +
                        "network policy than the one configured in the App's manifest.");
            }
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
     * current TrustKit configuration for the specified serverHostname. It can be used with most
     * network APIs (such as {@code HttpsUrlConnection}) to add SSL pinning validation to the
     * connections.
     *
     * <p>
     *     The {@code SSLSocketFactory} is configured for the supplied serverHostname, and will
     *     enforce this domain's pinning policy even if a redirection to a different domain occurs
     *     during the connection. Hence validation will always fail in the case of a redirection to
     *     a different domain.
     *     However, pinning validation is only meant to be used on the App's API server(s), and
     *     redirections to other domains should not happen in this scenario.
     * </p>
     *
     * @param serverHostname the server's hostname that the {@code SSLSocketFactory} will be used to
     *                       connect to. This hostname will be used to retrieve the pinning policy
     *                       from the current TrustKit configuration.
     */
    @NonNull
    public SSLSocketFactory getSSLSocketFactory(@NonNull String serverHostname) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{getTrustManager(serverHostname)}, null);

            return sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
            throw new IllegalStateException("Should not happen");
        }
    }


    /** Retrieve an {@code X509TrustManager} that implements SSL pinning validation based on the
     * current TrustKit configuration for the supplied hostname. It can be used with some network
     * APIs that let developers supply a trust manager to customize SSL validation.
     *
     * <p>
     *     The {@code X509TrustManager} is configured for the supplied serverHostname, and will
     *     enforce this domain's pinning policy even if a redirection to a different domain occurs
     *     during the connection. Hence validation will always fail in the case of a redirection to
     *     a different domain.
     *     However, pinning validation is only meant to be used on the App's API server(s), and
     *     redirections to other domains should not happen in this scenario.
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
