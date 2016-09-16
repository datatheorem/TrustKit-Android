package com.datatheorem.android.trustkit.reporting;


import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

// Very basic implementation to rate-limit identical reports to once a day
// TODO(ad): Remove public
public final class ReportsRateLimiter {
    private static final long MAX_SECONDS_BETWEEN_CACHE_RESET = 3600*24;
    private static Set<List<Object>> reportsCache = new HashSet<>();
    private static Date lastReportsCacheResetDate = new Date();

    public synchronized static boolean shouldRateLimit(final PinFailureReport report) {
        // Reset the cache if it was created more than 24 hours ago
        Date currentDate = new Date();
        long secondsSinceLastReset =
                (currentDate.getTime() / 1000) - (lastReportsCacheResetDate.getTime() / 1000);
        if (secondsSinceLastReset > MAX_SECONDS_BETWEEN_CACHE_RESET) {
            reportsCache.clear();
            lastReportsCacheResetDate = currentDate;
        }

        // Check to see if an identical report is already in the cache
        List<Object> cacheEntry = new ArrayList<Object>() {{
            add(report.getNotedHostname());
            add(report.getServerHostname());
            add(report.getServerPort());
            add(report.getValidatedCertificateChainAsPem());
            add(report.getValidationResult());
        }};
        boolean shouldRateLimitReport = reportsCache.contains(cacheEntry);
        if (!shouldRateLimitReport){
            reportsCache.add(cacheEntry);
        }
        return shouldRateLimitReport;
    }
}
