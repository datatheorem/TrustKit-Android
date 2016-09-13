package com.datatheorem.android.trustkit.reporting;

import android.content.Context;
import android.content.Intent;
import android.support.v4.content.LocalBroadcastManager;


/**
 * PinningEventBroadcastSender send a local broadcast message with the report
 */
// TODO(ad): Rename this to clarify that it is a broadcast
class PinningEventBroadcastSender {

    // TODO(ad): Choose the right ID and move it to the right class
    private static final String broadcastIdentifier = "test-id";

    public static final String TRUSTKIT_INTENT_SERVER_HOSTNAME_KEY =
            "TRUSTKIT_INTENT_SERVER_HOSTNAME_KEY";
    public static final String TRUSTKIT_INTENT_VALIDATION_DURATION_KEY =
            "TRUSTKIT_INTENT_VALIDATION_DURATION_KEY";
    public static final String TRUSTKIT_INTENT_NOTED_HOSTNAME_KEY =
            "TRUSTKIT_INTENT_NOTED_HOSTNAME_KEY";
    public static final String TRUSTKIT_INTENT_CERTIFICATE_CHAIN_KEY =
            "TRUSTKIT_INTENT_CERTIFICATE_CHAIN_KEY";
    public static final String TRUSTKIT_INTENT_VALIDATION_RESULT_KEY =
            "TRUSTKIT_INTENT_VALIDATION_RESULT_KEY";

    private Context applicationContext;

    public PinningEventBroadcastSender(Context applicationContext) {
        this.applicationContext = applicationContext.getApplicationContext();
    }

    // TODO(ad): Once pinning is implemented: Figure out where to call this
    public void send(final String serverHostname, final long validationDuration,
                     final String notedHostname, final String[] validatedCertificateChain,
                     final int validationResult){
        Intent intent = new Intent(broadcastIdentifier);

        intent.putExtra(TRUSTKIT_INTENT_SERVER_HOSTNAME_KEY, serverHostname);
        //todo(jb) add validation duration
//        intent.putExtra(TRUSTKIT_INTENT_VALIDATION_DURATION_KEY, 0);
        intent.putExtra(TRUSTKIT_INTENT_NOTED_HOSTNAME_KEY, notedHostname);
        intent.putExtra(TRUSTKIT_INTENT_CERTIFICATE_CHAIN_KEY, validatedCertificateChain);
        intent.putExtra(TRUSTKIT_INTENT_VALIDATION_RESULT_KEY, validationResult);
        LocalBroadcastManager.getInstance(applicationContext).sendBroadcast(intent);

    }
}
