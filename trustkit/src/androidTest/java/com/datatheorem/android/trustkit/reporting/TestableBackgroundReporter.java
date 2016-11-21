package com.datatheorem.android.trustkit.reporting;


import android.support.annotation.NonNull;

import java.net.URL;
import java.util.Set;

public class TestableBackgroundReporter extends BackgroundReporter {
    public TestableBackgroundReporter(String appPackageName, String appVersion, String appVendorId){
        super(appPackageName, appVersion, appVendorId);
    }

    @Override
    public void sendReport(@NonNull PinningFailureReport report, @NonNull Set<URL> reportUriSet) {
        super.sendReport(report, reportUriSet);
    }
}
