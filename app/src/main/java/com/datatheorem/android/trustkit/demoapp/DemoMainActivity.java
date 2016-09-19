package com.datatheorem.android.trustkit.demoapp;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import com.datatheorem.android.trustkit.TrustKit;

public class DemoMainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_demo_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        
        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);

//        final TrustKitConfiguration trustKitConfig = new TrustKitConfiguration();
//        PinnedDomainConfiguration datatheoremConfig = new PinnedDomainConfiguration.Builder()
//                .publicKeyHashes(new String[]{"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY="})
//                .shouldEnforcePinning(false)
//                .build();
//        trustKitConfig.put("www.datatheorem.com", datatheoremConfig);
//
        TextView textView = (TextView) findViewById(R.id.textview);

        TrustKit.initWithNetworkPolicy(this);
        textView.setText(TrustKit.getInstance().getConfiguration().findConfiguration("www.datatheorem.com").toString());

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_demo_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}

