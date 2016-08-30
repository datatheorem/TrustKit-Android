package com.datatheorem.android.trustkit.report;


import java.util.Date;
import java.util.HashSet;
import java.util.Set;

final class ReportsRateLimiter {
    private static final long INTERVAL_BETWEEN_REPORTS_CACHE_RESET = 3600*24;
    private static Set<PinFailureReport> cachePinFailureReports = null;
    private static Date lastReportCacheResetDate;

    public synchronized static boolean shouldRateLimit(PinFailureReport report) {
        if (cachePinFailureReports == null) {
            cachePinFailureReports = new HashSet<>();
        }

        if (lastReportCacheResetDate == null) {
            lastReportCacheResetDate = new Date();
        }

        if ((new Date().getTime() / 1000) - (lastReportCacheResetDate.getTime() / 1000) > INTERVAL_BETWEEN_REPORTS_CACHE_RESET) {
            cachePinFailureReports.clear();
            lastReportCacheResetDate = new Date();
        }

        boolean shouldRateLimitReport = cachePinFailureReports.contains(report);
        if (!shouldRateLimitReport){
            cachePinFailureReports.add(report);
        }

        return shouldRateLimitReport;
    }
}
