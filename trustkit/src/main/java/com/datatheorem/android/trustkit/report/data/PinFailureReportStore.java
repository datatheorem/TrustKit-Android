package com.datatheorem.android.trustkit.report.data;

/**
 * Interface to create classes to store a {@link PinFailureReport}
 */
public interface PinFailureReportStore {
    boolean save(PinFailureReport report);

}
