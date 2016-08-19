package com.datatheorem.android.trustkit.report.data;

import android.os.Process;

import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.utils.TrustKitLog;

import org.json.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public final class PinFailureReportDiskStore implements PinFailureReportStore {
    @Override
    public boolean save(PinFailureReport report) {
        File tmpDir = new File("/tmp");
        final File tmpFile = new File(tmpDir, String.valueOf(Process.getThreadPriority(Process.myTid()))+".tsk-report");
        try {
            String reportJson = report.toJson().toString();

            if (reportJson != null) {
                FileWriter fileWriter = new FileWriter(tmpFile);
                fileWriter.write(reportJson);
                fileWriter.flush();
                fileWriter.close();

                if (tmpFile.createNewFile()) {
                    TrustKitLog.i("Report for " + report.getServerHostname() + " created at " + tmpFile.getAbsolutePath());
                    return true;
                } else {
                    return false;
                }
            } else {
                //todo better handling the jsonobject.tostring problem and/or find a better message
                TrustKitLog.e("A problem happened with the report: \n " + report.toString());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }
}
