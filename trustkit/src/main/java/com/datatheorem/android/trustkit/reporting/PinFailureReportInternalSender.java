package com.datatheorem.android.trustkit.reporting;

import android.content.Context;
import android.content.Intent;
import android.support.v4.content.LocalBroadcastManager;


/**
 * PinFailureReportInternalSender send a local broadcast message with the report
 */
// TODO(ad): Rename this to clarify that it is a broadcast
// TODO(ad): This should send notifications also when pin validation was successful (to consumers can check the duration of each validation)
class PinFailureReportInternalSender {

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

    public PinFailureReportInternalSender(Context applicationContext) {
        this.applicationContext = applicationContext.getApplicationContext();
    }

    // TODO(ad): Rename this to BroadcastSomething
    // TODO(ad): Explicitely list the needed arguments and use them directly
    // TODO(ad): Once pinning is implemented: Figure out where to call this
    public void send(final PinFailureReport pinFailureReport) {
        Intent intent = new Intent(broadcastIdentifier);

        intent.putExtra(TRUSTKIT_INTENT_SERVER_HOSTNAME_KEY, pinFailureReport.getServerHostname());
        //todo(jb) add validation duration
//        intent.putExtra(TRUSTKIT_INTENT_VALIDATION_DURATION_KEY, 0);
        intent.putExtra(TRUSTKIT_INTENT_NOTED_HOSTNAME_KEY, pinFailureReport.getNotedHostname());
        intent.putExtra(TRUSTKIT_INTENT_CERTIFICATE_CHAIN_KEY, pinFailureReport.getValidatedCertificateChain());
        intent.putExtra(TRUSTKIT_INTENT_VALIDATION_RESULT_KEY, pinFailureReport.getValidationResult());
        LocalBroadcastManager.getInstance(applicationContext).sendBroadcast(intent);

    }
}
