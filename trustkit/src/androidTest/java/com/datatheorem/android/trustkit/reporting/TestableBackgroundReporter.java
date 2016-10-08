package com.datatheorem.android.trustkit.reporting;


import java.net.URL;
import java.util.Set;

public class TestableBackgroundReporter extends BackgroundReporter {
    public TestableBackgroundReporter(boolean shouldRateLimitsReports, String appPackageName,
                                      String appVersion, String appVendorId) {
        super(shouldRateLimitsReports, appPackageName, appVersion, appVendorId);
    }

    @Override
    public void sendReport(PinningFailureReport report, Set<URL> reportUriSet) {
        super.sendReport(report, reportUriSet);
    }
}
