package com.datatheorem.android.trustkit.demoapp;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;
import android.widget.Toast;

import com.datatheorem.android.trustkit.TrustKit;

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class DemoMainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_demo_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        TextView textView = (TextView) findViewById(R.id.textview);

        TrustKit.initializeWithNetworkSecurityConfiguration(this);
        textView.setText(TrustKit.getInstance().getConfiguration().getDebugCaCertificates().toString());
        OkHttpClient client = new OkHttpClient().newBuilder().sslSocketFactory(TrustKit.getInstance().getSSLSocketFactory()).build();

        try {
            Request request = new Request.Builder().url(new URL("https://www.yahoo.com")).build();
            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    if ((e.getCause() instanceof CertificateException
                      && (e.getCause().getMessage().startsWith("Pin verification failed")))) {
                        Toast.makeText(DemoMainActivity.this, "Pin verification failed", Toast.LENGTH_LONG ).show();
                    }
                }
                @Override
                public void onResponse(Call call, Response response) throws IOException {
//                    Toast.makeText(DemoMainActivity.this, "w00t", Toast.LENGTH_LONG ).show();
                    Log.d("TrustKit", "w00t");

                }
            });
        } catch (IOException e) {

                Toast.makeText(this, e.getLocalizedMessage(), Toast.LENGTH_LONG ).show();

        }
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

