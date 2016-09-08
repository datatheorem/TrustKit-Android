package com.datatheorem.android.trustkit.reporting;

import java.util.Arrays;

class PinFailureInfo {
    protected String notedHostname;
    protected String hostname;
    protected int port;
    protected String[] validatedCertificateChain;
    protected String[] knownPins;
    protected int validationResult;


    public PinFailureInfo(PinFailureReport report) {
        notedHostname = report.getNotedHostname();
        hostname = report.getServerHostname();
        port = report.getPort();
        validatedCertificateChain = report.getValidatedCertificateChain();
        knownPins = report.getKnownPins();
        validationResult = report.getValidationResult();
    }

    /*
    Based on http://stackoverflow.com/questions/16069106/how-to-compare-two-java-objects
     */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof PinFailureInfo)) {
            return false;
        }

        PinFailureInfo that = (PinFailureInfo) obj;

        return this.notedHostname.equals(that.notedHostname)
                && this.hostname.equals(that.hostname)
                && this.port == that.port
                && Arrays.equals(this.validatedCertificateChain, that.validatedCertificateChain)
                && Arrays.equals(this.knownPins, that.knownPins)
                && this.validationResult == that.validationResult;
    }

    /*
    Based on http://stackoverflow.com/questions/113511/best-implementation-for-hashcode-method
     */
    @Override
    public int hashCode() {
        int hashCode = 1;

        hashCode = hashCode * 37 + this.notedHostname.hashCode();
        hashCode = hashCode * 37 + this.hostname.hashCode();
        hashCode = hashCode * 37 + this.port;
        hashCode = hashCode * 37 + Arrays.hashCode(this.validatedCertificateChain);
        hashCode = hashCode * 37 + Arrays.hashCode(this.knownPins);
        hashCode = hashCode * 37 + this.validationResult;

        return hashCode;
    }
}

