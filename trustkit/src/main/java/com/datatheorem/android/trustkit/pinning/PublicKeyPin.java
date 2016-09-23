package com.datatheorem.android.trustkit.pinning;

import android.util.Base64;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;


/**
 * A pin is the base64-encoded SHA-256 hash of the certificate's Subject Public Key Info, as
 * described in the HPKP RFC https://tools.ietf.org/html/rfc7469s .
 */
public final class PublicKeyPin {

    private String pin;

    public PublicKeyPin(Certificate certificate) {
        // Generate the certificate's spki pin
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Should never happen");
        }
        digest.reset();

        byte[] spki = certificate.getPublicKey().getEncoded();
        byte[] spkiHash = digest.digest(spki);
        pin = Base64.encodeToString(spkiHash, Base64.DEFAULT).trim();
    }

    public PublicKeyPin(String spkiPin) {
        // Validate the format of the pin
        byte[] spkiSha256Hash = Base64.decode(spkiPin, Base64.DEFAULT);
        if (spkiSha256Hash.length != 32) {
            throw new IllegalArgumentException("Invalid pin: length is not 32 bytes");
        }
        pin = spkiPin;
    }

    @Override
    public boolean equals(Object arg0) {
        return (arg0 instanceof PublicKeyPin) && arg0.toString().equals(this.toString());
    }

    @Override
    public int hashCode() {
        return pin.hashCode();
    }

    @Override
    public String toString(){ return pin; }
}
