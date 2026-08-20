package com.datatheorem.android.trustkit

import java.net.URL
import java.util.Collections
import java.util.LinkedHashMap

class TrustKitOptions
private constructor(val defaultReportUrl: URL?, defaultReportHeaders: Map<String, String>) {
    val defaultReportHeaders: Map<String, String> =
        Collections.unmodifiableMap(LinkedHashMap(defaultReportHeaders))

    class Builder {
        private var defaultReportUrl: URL? = null
        private val defaultReportHeaders = linkedMapOf<String, String>()

        fun setDefaultReportUrl(defaultReportUrl: URL): Builder = apply {
            val protocol = defaultReportUrl.protocol
            require(
                protocol.equals("http", ignoreCase = true) ||
                    protocol.equals("https", ignoreCase = true)
            ) {
                "The default report URL must use HTTP or HTTPS"
            }
            this.defaultReportUrl = defaultReportUrl
        }

        fun addDefaultReportHeader(name: String, value: String): Builder = apply {
            defaultReportHeaders[name] = value
        }

        fun build(): TrustKitOptions {
            check(!(defaultReportHeaders.isNotEmpty() && defaultReportUrl == null)) {
                "A default report URL must be configured before adding report headers"
            }
            return TrustKitOptions(defaultReportUrl, defaultReportHeaders)
        }
    }
}
