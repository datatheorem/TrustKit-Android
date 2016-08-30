package com.datatheorem.android.trustkit.report;

import java.net.URL;

// TODO(ad): Remove it after tweaking the notification/broadcast thing
interface PinFailureReportSender {
    //todo this class should not do pinning
    void send(URL reportURI, PinFailureReport pinFailureReport);
}
