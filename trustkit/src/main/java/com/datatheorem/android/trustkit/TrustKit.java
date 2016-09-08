package com.datatheorem.android.trustkit;

import android.content.Context;
import android.content.res.XmlResourceParser;

import com.datatheorem.android.trustkit.config.TrustKitConfiguration;
import com.datatheorem.android.trustkit.reporting.BackgroundReporter;


public class TrustKit {

    private Context appContext;
    private TrustKitConfiguration trustKitConfiguration;
    private BackgroundReporter backgroundReporter;
    private static TrustKit trustKitInstance;


    private TrustKit(Context context, TrustKitConfiguration trustKitConfiguration) {
        this.appContext = context;
        this.trustKitConfiguration = trustKitConfiguration;
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
        init(context, TrustKitConfiguration.fromXmlPolicy(parser));
    }

    public static void init(Context appContext, TrustKitConfiguration trustKitConfiguration) {
        if (trustKitInstance == null) {
            trustKitInstance = new TrustKit(appContext, trustKitConfiguration);
        }
        else {
            throw new IllegalStateException("Already instantiated");
        }
    }

    public TrustKitConfiguration getConfiguration() { return trustKitConfiguration; }
    public BackgroundReporter getReporter() { return backgroundReporter; }
    public Context getAppContext() {
        return appContext;
    }

}
