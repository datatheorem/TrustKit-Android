package com.datatheorem.android.trustkit.report;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.content.LocalBroadcastManager;

import java.net.URL;


/**
 * PinFailureReportInternalSender send a local broadcast message with the report
 */
class PinFailureReportInternalSender implements PinFailureReportSender {
    private String broadcastIdentifier;
    private Context applicationContext;

    public PinFailureReportInternalSender(Context applicationContext, String broadcastIdentifier) {
        this.applicationContext = applicationContext.getApplicationContext();
        this.broadcastIdentifier = broadcastIdentifier;
    }

    @Override
    public void send(final URL reportURI, final PinFailureReport pinFailureReport) {
        Intent intent = new Intent(broadcastIdentifier);
        Bundle reportBundle = new Bundle();
        // TODO(ad): Let's send the raw data and some timing information (we can implement later)
        // userInfo:@{kTSKValidationDurationNotificationKey: @(validationDuration),
        // kTSKValidationDecisionNotificationKey: @(finalTrustDecision),
        // kTSKValidationResultNotificationKey: @(validationResult),
        // kTSKValidationCertificateChainNotificationKey: certificateChain,
        // kTSKValidationNotedHostnameNotificationKey: notedHostname,
        // kTSKValidationServerHostnameNotificationKey: serverHostname}];
        reportBundle.putSerializable("report", pinFailureReport);
        intent.putExtras(reportBundle);
        LocalBroadcastManager.getInstance(applicationContext).sendBroadcast(intent);

    }
}
