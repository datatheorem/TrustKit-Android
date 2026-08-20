@file:JvmName("VendorIdentifier")

package com.datatheorem.android.trustkit.utils

import android.content.Context
import android.content.Context.MODE_PRIVATE
import android.preference.PreferenceManager
import java.util.UUID

/**
 * When TrustKit sends a report, it also sends a randomly-generated identifier to uniquely identify
 * a specific App install (ie. an instance of the App running on a specific device). It is the least
 * intrusive way to detect reports coming from the same device.
 */
private const val TRUSTKIT_VENDOR_ID = "TRUSTKIT_VENDOR_ID"

fun getOrCreate(appContext: Context): String {
    // new sdk preferences
    val tkSharedPreferences =
        appContext.getSharedPreferences("DataTheoremPreferences", MODE_PRIVATE)

    val appVendorId = tkSharedPreferences.getString(TRUSTKIT_VENDOR_ID, "") ?: ""
    if (appVendorId.isNotBlank()) return appVendorId

    // legacy default preferences
    val defaultPreferences = PreferenceManager.getDefaultSharedPreferences(appContext)

    val defaultAppVendorId = defaultPreferences.getString(TRUSTKIT_VENDOR_ID, "") ?: ""
    // we have a legacy id, write it to the new preferences before returning
    if (defaultAppVendorId.isNotBlank()) {
        tkSharedPreferences.edit().putString(TRUSTKIT_VENDOR_ID, defaultAppVendorId).apply()
        return defaultAppVendorId
    }

    // we don't have an id, generate one
    TrustKitLog.i("Generating new vendor identifier...")
    val newId = UUID.randomUUID().toString()
    tkSharedPreferences.edit().putString(TRUSTKIT_VENDOR_ID, newId).apply()

    return newId
}
