package com.datatheorem.android.trustkit.demoappkotlin

import android.content.IntentFilter
import android.os.AsyncTask
import android.os.Bundle
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.TextView
import com.datatheorem.android.trustkit.TrustKit
import com.datatheorem.android.trustkit.reporting.BackgroundReporter
import java.io.IOException
import java.net.MalformedURLException
import java.net.URL
import javax.net.ssl.HttpsURLConnection


class DemoMainActivity : AppCompatActivity() {
    private lateinit var pinningFailureReportBroadcastReceiver: PinningFailureReportBroadcastReceiver

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_demo_main)
        val toolbar = findViewById<View>(R.id.toolbar) as Toolbar
        setSupportActionBar(toolbar)
        val textView = findViewById<View>(R.id.textview) as TextView

        // Initialize TrustKit with the default path for the Network Security Configuration which is
        // res/xml/network_security_config.xml
        TrustKit.initializeWithNetworkSecurityConfiguration(this)
        // Connect to the URL with valid pins - this connection will succeed
        DownloadWebpageTask().execute("https://www.datatheorem.com")

        // Connect to the URL with invalid pins - this connection will fail
        DownloadWebpageTask().execute("https://www.google.com")

        textView.text = "Connection results are in the logs"

        // Adding a local broadcast receiver to listen for validation report events
        pinningFailureReportBroadcastReceiver =  PinningFailureReportBroadcastReceiver()
        val intentFilter = IntentFilter(BackgroundReporter.REPORT_VALIDATION_EVENT)
        LocalBroadcastManager.getInstance(this.applicationContext)
            .registerReceiver(pinningFailureReportBroadcastReceiver,intentFilter)
    }

    override fun onDestroy() {
        LocalBroadcastManager.getInstance(this.applicationContext)
                .unregisterReceiver(pinningFailureReportBroadcastReceiver)
        super.onDestroy()
    }

    private inner class DownloadWebpageTask : AsyncTask<String, Void, String>() {

        override fun doInBackground(vararg params: String): String {
            try {
                val url = URL(params[0])
                val connection: HttpsURLConnection?
                connection = url.openConnection() as HttpsURLConnection
                connection.sslSocketFactory = TrustKit.getInstance().getSSLSocketFactory(url.host)
                val inputStream = connection.inputStream
            } catch (e: MalformedURLException) {
                e.printStackTrace()
            } catch (e: IOException) {
                e.printStackTrace()
                return "Failed to connect to: " + params[0]
            }

            return "Successfully connected to: " + params[0]
        }

        override fun onPostExecute(result: String) {
            // Log the response
            Log.i(DEBUG_TAG, result)
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_demo_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        val id = item.itemId


        return if (id == R.id.action_settings) {
            true
        } else super.onOptionsItemSelected(item)

    }

    companion object {

        internal const val DEBUG_TAG = "TrustKit-Demo"
    }
}

