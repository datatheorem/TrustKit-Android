package com.datatheorem.android.trustkit.report.internals;

import com.datatheorem.android.trustkit.report.data.PinFailureReport;

import java.net.URL;

public interface PinFailureReportSender {
    //todo this class should not do pinning
    void send(URL reportURI, PinFailureReport pinFailureReport);
}
