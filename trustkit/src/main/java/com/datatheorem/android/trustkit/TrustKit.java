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
     * For more information about pinning configuration using Network Security Configuration, see
     * https://developer.android.com/training/articles/security-config.html#CertificatePinning.
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
     * For more information about pinning configuration using Network Security Configuration, see
     * https://developer.android.com/training/articles/security-config.html#CertificatePinning.
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

    /** Retrieve an SSLSSocketFactory that implements SSL pinning validation based on the current
     * TrustKit configuration. It can be used with most network APIs (such as HttpsUrlConnection) to
     * add SSL pinning validation to the connections.
     */
    @NonNull
    public SSLSocketFactory getSSLSocketFactory() {
        return new TrustKitSSLSocketFactory();
    }

    /** Retrieve an X509TrustManager that implements SSL pinning validation based on the current
     * TrustKit configuration for the supplied hostname. It can be used with some network APIs that
     * let developers supply a trust manager to customize SSL validation.
     *
     * @param serverHostname the server's hostname that the X509TrustManager will be used to connect
     *                       to. This hostname will be used to retrieve the pinning policy from the
     *                       current TrustKit configuration.
     */
    @NonNull
    public X509TrustManager getTrustManager(@NonNull String serverHostname) {
        return TrustManagerBuilder.getTrustManager(serverHostname);
    }
}
