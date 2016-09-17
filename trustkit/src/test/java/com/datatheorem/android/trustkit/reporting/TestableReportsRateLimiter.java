package com.datatheorem.android.trustkit.reporting;


import java.util.Date;

class TestableReportsRateLimiter extends ReportsRateLimiter {

    public static void setLastReportsCacheResetDate(Date newDate) {
        lastReportsCacheResetDate = newDate;
    }
}
