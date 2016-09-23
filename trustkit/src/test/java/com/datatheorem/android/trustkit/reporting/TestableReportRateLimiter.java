package com.datatheorem.android.trustkit.reporting;


import java.util.Date;

class TestableReportRateLimiter extends ReportRateLimiter {

    public static void setLastReportsCacheResetDate(Date newDate) {
        lastReportsCacheResetDate = newDate;
    }
}
