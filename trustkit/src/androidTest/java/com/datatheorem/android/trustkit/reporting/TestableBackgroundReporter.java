package com.datatheorem.android.trustkit.reporting;


import android.content.Context;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import java.net.URL;
import java.util.Set;


@RequiresApi(api = 16)
public class TestableBackgroundReporter extends BackgroundReporter {
    public TestableBackgroundReporter(Context context, String appPackageName, String appVersion, String appVendorId){
        super(context, appPackageName, appVersion, appVendorId);
    }

    @Override
    public void sendReport(@NonNull PinningFailureReport report, @NonNull Set<URL> reportUriSet) {
        super.sendReport(report, reportUriSet);
    }
}
