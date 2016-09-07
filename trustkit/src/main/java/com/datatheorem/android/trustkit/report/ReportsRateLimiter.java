package com.datatheorem.android.trustkit.report;


import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

final class ReportsRateLimiter {
    private static final long INTERVAL_BETWEEN_REPORTS_CACHE_RESET = 3600*24;
    private static Set<PinFailureInfo> cachePinFailureReport = null;
    private static Date lastReportCacheResetDate;

    public synchronized static boolean shouldRateLimit(PinFailureReport report) {
        if (cachePinFailureReport == null) {
            cachePinFailureReport = new HashSet<>();
        }

        if (lastReportCacheResetDate == null) {
            lastReportCacheResetDate = new Date();
        }

        if ((new Date().getTime() / 1000) - (lastReportCacheResetDate.getTime() / 1000)
                > INTERVAL_BETWEEN_REPORTS_CACHE_RESET) {
            cachePinFailureReport.clear();
            lastReportCacheResetDate = new Date();
        }


        PinFailureInfo pinFailureInfo = new PinFailureInfo(report);

        boolean shouldRateLimitReport = cachePinFailureReport.contains(pinFailureInfo);

        if (!shouldRateLimitReport){
            cachePinFailureReport.add(pinFailureInfo);
        }

        return shouldRateLimitReport;
    }
}
