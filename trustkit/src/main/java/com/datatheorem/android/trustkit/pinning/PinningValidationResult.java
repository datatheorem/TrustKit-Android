package com.datatheorem.android.trustkit.pinning;


public enum PinningValidationResult {
    // The server trust was successfully evaluated and contained at least one of the configured pins
    SUCCESS,

    // The server trust was successfully evaluated but did not contain any of the configured pins
    FAILED,

    // The server trust's evaluation failed: the server's certificate chain is not trusted
    FAILED_CERTIFICATE_CHAIN_NOT_TRUSTED,

    // Not used on Android
    ERROR_INVALID_PARAMETERS,

    // Not used on Android
    FAILED_USER_DEFINED_TRUST_ANCHOR,

    // Not used on Android
    ERROR_COULD_NOT_GENERATE_SPKI_HASH
}
