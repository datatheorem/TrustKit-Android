package com.datatheorem.android.trustkit.config;

public final class ConfigException extends RuntimeException{
        public ConfigException(String detailMessage) {
            super(detailMessage);
        }

        public ConfigException(Throwable throwable) {
            super(throwable);
        }
    }