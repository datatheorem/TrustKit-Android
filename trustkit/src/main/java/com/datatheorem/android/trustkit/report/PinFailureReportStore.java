package com.datatheorem.android.trustkit.report;

// TODO(ad): Will go away
/**
 * Interface to create classes to store a {@link PinFailureReport}
 */
interface PinFailureReportStore {
    boolean save(PinFailureReport report);

}
