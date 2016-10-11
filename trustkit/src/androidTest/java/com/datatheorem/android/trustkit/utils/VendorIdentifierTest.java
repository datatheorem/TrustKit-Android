package com.datatheorem.android.trustkit.utils;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;


@RunWith(AndroidJUnit4.class)
public class VendorIdentifierTest {

    @Test
    public void test() {
        Context context = InstrumentationRegistry.getContext();
        String vendorId = VendorIdentifier.getOrCreate(context);
        String vendorId2 = VendorIdentifier.getOrCreate(context);
        assertNotNull(vendorId);
        assertEquals(vendorId, vendorId2);
    }
}
