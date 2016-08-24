package com.datatheorem.android.trustkit.report;

import java.net.URL;

interface PinFailureReportSender {
    //todo this class should not do pinning
    void send(URL reportURI, PinFailureReport pinFailureReport);
}
