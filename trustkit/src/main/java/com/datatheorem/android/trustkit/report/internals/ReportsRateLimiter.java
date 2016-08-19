package com.datatheorem.android.trustkit.report.internals;

import com.datatheorem.android.trustkit.report.data.PinFailureReport;

public final class ReportsRateLimiter {
    public static boolean shouldRateLimit(PinFailureReport report) {
        return false;

    }
}
