package com.datatheorem.android.trustkit.report;

/**
 * Interface to create classes to store a {@link PinFailureReport}
 */
interface PinFailureReportStore {
    boolean save(PinFailureReport report);

}
