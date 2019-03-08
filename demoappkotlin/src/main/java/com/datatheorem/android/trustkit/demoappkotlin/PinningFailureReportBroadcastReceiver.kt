package com.datatheorem.android.trustkit.demoappkotlin

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.datatheorem.android.trustkit.reporting.BackgroundReporter

/**
 * Class that provides an example broadcast receiver
 *
 * <p>
 *     Applications using TrustKit can listen for local broadcasts and receive the same report that
 *     would be sent to the report_url.
 * </p>
 **/
class PinningFailureReportBroadcastReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val result = intent.getSerializableExtra(BackgroundReporter.EXTRA_REPORT)
        Log.i(DemoMainActivity.DEBUG_TAG, result.toString())
    }

}
