package com.datatheorem.android.trustkit.report.internals;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.content.LocalBroadcastManager;

import com.datatheorem.android.trustkit.report.data.PinFailureReport;

import java.net.URL;


/**
 * PinFailureReportInternalSender send a local broadcast message with the report
 */
public class PinFailureReportInternalSender implements PinFailureReportSender {
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
        reportBundle.putSerializable("report", pinFailureReport);
        intent.putExtras(reportBundle);
        LocalBroadcastManager.getInstance(applicationContext).sendBroadcast(intent);
    }
}
