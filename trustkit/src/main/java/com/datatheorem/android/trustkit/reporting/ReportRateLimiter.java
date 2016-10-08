package com.datatheorem.android.trustkit.reporting;


import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

// Very basic implementation to rate-limit identical reports to once a day
class ReportRateLimiter {

    private static final long MAX_SECONDS_BETWEEN_CACHE_RESET = 3600*24;
    private static Set<List<Object>> reportsCache = new HashSet<>();
    protected static Date lastReportsCacheResetDate = new Date();

    synchronized static boolean shouldRateLimit(final PinningFailureReport report) {
        // Reset the cache if it was created more than 24 hours ago
        Date currentDate = new Date();
        long secondsSinceLastReset =
                (currentDate.getTime() / 1000) - (lastReportsCacheResetDate.getTime() / 1000);
        if (secondsSinceLastReset > MAX_SECONDS_BETWEEN_CACHE_RESET) {
            reportsCache.clear();
            lastReportsCacheResetDate = currentDate;
        }

        // Check to see if an identical report is already in the cache
        List<Object> cacheEntry = new ArrayList<>();
        cacheEntry.add(report.getNotedHostname());
        cacheEntry.add(report.getServerHostname());
        cacheEntry.add(report.getServerPort());
        cacheEntry.add(report.getValidatedCertificateChainAsPem());
        cacheEntry.add(report.getValidationResult());

        boolean shouldRateLimitReport = reportsCache.contains(cacheEntry);
        if (!shouldRateLimitReport){
            reportsCache.add(cacheEntry);
        }
        return shouldRateLimitReport;
    }
}
