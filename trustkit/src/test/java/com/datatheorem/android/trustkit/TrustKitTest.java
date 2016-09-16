package com.datatheorem.android.trustkit;

import android.content.Context;
import android.os.Build;

import com.datatheorem.android.trustkit.TrustKit;
import com.datatheorem.android.trustkit.TrustKitConfiguration;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.robolectric.RobolectricGradleTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

@Config(constants = BuildConfig.class, sdk = 23)
@RunWith(RobolectricGradleTestRunner.class)
public class TrustKitTest{


    @Mock
    TrustKitConfiguration trustKitConfiguration;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }


    @Test
    public void initTest(){
        //TrustKit.init(RuntimeEnvironment.application, trustKitConfiguration);
        Assert.assertNotNull(TrustKit.getInstance());
        Assert.assertNotNull(TrustKit.getInstance().getConfiguration());
        Assert.assertNotNull(TrustKit.getInstance().getReporter());
    }

}
