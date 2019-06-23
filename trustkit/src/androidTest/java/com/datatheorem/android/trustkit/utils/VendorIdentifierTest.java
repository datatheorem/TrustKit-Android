package com.datatheorem.android.trustkit.utils;

import android.content.Context;

import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;


public class VendorIdentifierTest {

    @Test
    public void test() {
        Context context = InstrumentationRegistry.getInstrumentation().getContext();
        String vendorId = VendorIdentifier.getOrCreate(context);
        String vendorId2 = VendorIdentifier.getOrCreate(context);
        assertNotNull(vendorId);
        assertEquals(vendorId, vendorId2);
    }
}
