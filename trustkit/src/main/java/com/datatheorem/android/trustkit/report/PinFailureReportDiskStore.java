package com.datatheorem.android.trustkit.report;

import android.content.Context;
import android.os.Process;

import com.datatheorem.android.trustkit.utils.TrustKitLog;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

class PinFailureReportDiskStore implements PinFailureReportStore {
    Context applicationContext;

    public PinFailureReportDiskStore(Context applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public boolean save(PinFailureReport report) {
        File tmpDir = new File(applicationContext.getFilesDir(), "/tmp/");
        tmpDir.mkdir();

        try {
            final File tmpFile = new File(tmpDir, String.valueOf(Process.getThreadPriority(Process.myUid()))+".tsk-report");

           try{
                String reportJson = report.toJson().toString();

                tmpFile.createNewFile();

                FileWriter fileWriter = new FileWriter(tmpFile);
                fileWriter.write(reportJson);
                fileWriter.flush();
                fileWriter.close();

                if (tmpFile.exists()) {

                    TrustKitLog.i("Report for " + report.getServerHostname() + " created at " + tmpFile.getAbsolutePath());
                    return true;
                } else {
                    System.out.print("test");
                    return false;
                }
            } catch (NullPointerException npe) {

                //todo better handling the jsonobject.tostring problem and/or find a better message

                TrustKitLog.e("A problem happened with the report: \n " + report.toString());
                return false;

            }
        } catch (IOException e) {
            System.out.print(e.getMessage());
            e.printStackTrace();
        }

        return false;
    }
}
