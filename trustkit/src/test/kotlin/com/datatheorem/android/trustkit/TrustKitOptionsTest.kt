package com.datatheorem.android.trustkit

import java.net.URL
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class TrustKitOptionsTest {
    @Test
    fun defaultOptions() {
        val options = TrustKitOptions.Builder().build()

        assertNull(options.defaultReportUrl)
        assertTrue(options.defaultReportHeaders.isEmpty())
    }

    @Test
    fun configuredOptionsAreImmutable() {
        val reportUrl = URL("https://reports.example.com/pinning")
        val options =
            TrustKitOptions.Builder()
                .setDefaultReportUrl(reportUrl)
                .addDefaultReportHeader("Authorization", "Bearer secret")
                .build()

        assertEquals(reportUrl, options.defaultReportUrl)
        assertEquals("Bearer secret", options.defaultReportHeaders["Authorization"])

        expectException<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (options.defaultReportHeaders as MutableMap<String, String>)["X-Test"] = "value"
        }
    }

    @Test
    fun headersRequireOverriddenDefaultUrl() {
        expectException<IllegalStateException> {
            TrustKitOptions.Builder()
                .addDefaultReportHeader("Authorization", "Bearer secret")
                .build()
        }
    }

    @Test
    fun nonHttpReportUrlIsRejected() {
        expectException<IllegalArgumentException> {
            TrustKitOptions.Builder().setDefaultReportUrl(URL("ftp://example.com/report"))
        }
    }

    private fun assertHeaderRejected(name: String, value: String) {
        expectException<IllegalArgumentException> {
            TrustKitOptions.Builder()
                .setDefaultReportUrl(URL("https://reports.example.com/pinning"))
                .addDefaultReportHeader(name, value)
        }
    }

    private inline fun <reified T : Throwable> expectException(block: () -> Unit) {
        try {
            block()
            fail("Expected ${T::class.java.simpleName}")
        } catch (throwable: Throwable) {
            if (throwable !is T) {
                throw throwable
            }
        }
    }
}
