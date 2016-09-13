package com.datatheorem.android.trustkit.pinning;

import com.datatheorem.android.trustkit.config.ConfigurationException;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SubjectPublicKeyInfoPin {
    private String pin;

    public SubjectPublicKeyInfoPin(String publicKeyHash) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            if (messageDigest.digest(publicKeyHash.getBytes("UTF-8")).length < 32) {
                throw new ConfigurationException("Invalid pin");
            }

            pin = publicKeyHash;
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new ConfigurationException("Invalid pin");
        }
    }

    public String get(){ return pin;}
}
