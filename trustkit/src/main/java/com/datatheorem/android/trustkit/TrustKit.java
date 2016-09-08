package com.datatheorem.android.trustkit;

import android.content.Context;
import android.content.res.XmlResourceParser;

import com.datatheorem.android.trustkit.config.TrustKitConfig;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;


public class TrustKit {

    private Context appContext;
    private TrustKitConfig trustKitConfig;
    private BackgroundReporter backgroundReporter;
    private static TrustKit trustKitInstance;


    private TrustKit(Context context, TrustKitConfig trustKitConfig) {
        this.appContext = context;
        this.trustKitConfig = trustKitConfig;
        this.backgroundReporter = new BackgroundReporter(true);
    }

    public static TrustKit getInstance() {
        return trustKitInstance;
    }

    public static void initWithNetworkPolicy(Context context) {
        final int networkSecurityConfigId = context.getResources().getIdentifier(
                "network_security_config", "xml", context.getPackageName()
        );

        XmlResourceParser parser = context.getResources().getXml(networkSecurityConfigId);
        init(context, TrustKitConfig.fromNetworkSecurityConfig(parser));
    }

    public static void init(Context appContext, TrustKitConfig trustKitConfig) {
        if (trustKitInstance == null) {
            trustKitInstance = new TrustKit(appContext, trustKitConfig);
        }
        else {
            throw new IllegalStateException("Already instantiated");
        }
    }

    public TrustKitConfig getConfiguration() { return trustKitConfig; }
    public BackgroundReporter getReporter() { return backgroundReporter; }
    public Context getAppContext() {
        return appContext;
    }

}
