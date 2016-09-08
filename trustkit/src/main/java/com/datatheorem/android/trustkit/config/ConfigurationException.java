package com.datatheorem.android.trustkit.config;

public final class ConfigurationException extends RuntimeException {
        public ConfigurationException(String detailMessage) {
            super(detailMessage);
        }

        public ConfigurationException(Throwable throwable) {
            super(throwable);
        }
}