TrustKit Android
============


[![Build Status](https://travis-ci.org/datatheorem/TrustKit-Android.svg?branch=master)](https://travis-ci.org/datatheorem/TrustKit-Android)
[![API](https://img.shields.io/badge/API-15%2B-blue.svg?style=flat)](https://android-arsenal.com/api?level=15)

**TrustKit Android** is an open source library that makes it easy to deploy SSL public key pinning in any Android App.


Overview
--------

TrustKit Android works by extending the [Android N Network Security Configuration](https://developer.android.com/training/articles/security-config.html) in two ways:

* It provides support for the `<pin-set>` (for SSL pinning) and `<debug-overrides>` functionality of the Network Security Configuration to earlier versions of Android, down to API level 17. This allows Apps that support versions of Android earlier than N to implement SSL pinning in a way that is future-proof.
* It adds the ability to send reports when pinning validation failed for a specific connection. Reports have a format that is similar to the report-uri feature of [HTTP Public Key Pinning](https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning) and [TrustKit iOS](https://github.com/datatheorem/trustkit).

For better compatibility, TrustKit will also run on API levels 15 and 16 but its functionality will be disabled.


Getting Started
----------------

* Read the [Getting Started guide](https://github.com/datatheorem/TrustKit-Android/blob/master/docs/getting-started.md).
* Check out the [API documentation](https://datatheorem.github.io/TrustKit-Android/documentation/).
* The [iOS version of TrustKit](https://github.com/datatheorem/TrustKit) was initially released at the Black Hat USA 2015 conference.


Sample Usage
---------------


### Adding TrustKit as a Dependency

Add TrustKit to your project's _build.gradle_:

`compile 'com.datatheorem.truskit:trustkit-android:'`

### Configuring a Pinning Policy

Deploying SSL pinning in the App requires initializing TrustKit with a pinning policy (domains, pins, and additional settings). The policy is wrapped in the official [Android N Network Security Configuration](https://developer.android.com/training/articles/security-config.html) i.e :

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <!-- Pin the domain www.datatheorem.com -->
  <!-- Official Android N API -->
  <domain-config>
    <domain>www.datatheorem.com</domain>
    <pin-set>
      <pin digest="SHA-256">k3XnEYQCK79AtL9GYnT/nyhsabas03V+bhRQYHQbpXU=</pin>
      <pin digest="SHA-256">2kOi4HdYYsvTR1sTIR7RHwlf2SescTrpza9ZrWy7poQ=</pin>
    </pin-set>
    <!-- TrustKit Android API -->
    <!-- Do not enforce pinning validation -->
    <trustkit-config enforcePinning="false">
      <!-- Add a reporting URL for pin validation reports -->
      <report-uri>http://report.datatheorem.com/log_report</report-uri>
    </trustkit-config>
  </domain-config>
  <debug-overrides>
    <trust-anchors>
      <!-- For debugging purposes, add a debug CA and override pins -->
      <certificates overridePins="true" src="@raw/debugca" />
    </trust-anchors>
  </debug-overrides>
</network-security-config>
```


### Initializing TrustKit with the Pinning Policy

The path to the XML policy should then be specified [in the App's manifest](https://developer.android.com/training/articles/security-config.html#manifest) in order to enable it as the App's [Network Security Configuration](https://developer.android.com/training/articles/security-config.html) on Android N:

```
<?xml version="1.0" encoding="utf-8"?>
<manifest ... >
    <application android:networkSecurityConfig="@xml/network_security_config"
                    ... >
        ...
    </application>
</manifest>

```

Then, TrustKit should be initialized with the same path:

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
  super.OnCreate(savedInstanceState);

  // Using the default path - res/xml/network_security_config.xml
  TrustKit.initializeWithNetworkSecurityConfiguration(this);

  // OR using a custom resource (TrustKit can't be initialized twice)
  TrustKit.initializeWithNetworkSecurityConfiguration(this, R.id.my_custom_network_security_config);

  URL url = new URL("https://www.datatheorem.com");
  String serverHostname = url.getHost();

  // HttpsUrlConnection
  HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
  connection.setSSLSocketFactory(TrustKit.getInstance().getSSLSocketFactory(serverHostname));

  // OkHttp 3
  OkHttpClient client =
    new OkHttpClient().newBuilder()
    .sslSocketFactory(TrustKit.getInstance().getSSLSocketFactory(serverHostname),
                      TrustKit.getInstance().getTrustManager(serverHostname))
    .build();
}
```

Once TrustKit has been initialized and the client or connection's `SSLSocketFactory` has been set, it will verify the server's certificate chain against the configured pinning policy whenever an HTTPS connection is initiated. If a report URI has been configured, the App will also send reports to the specified URI whenever a pin validation failure occurred.


Limitations
----------

On Android N devices, TrustKit uses the OS's implementation of pinning, and it is not affected by the following limitations.

On Android M and earlier devices, TrustKit provides uses its own implementation of pinning that is mostly-compatible with Android N's pinning behavior. However, in order to keep the code base as simple as possible, it has the following limitations:

* The pinning policy will only be applied to connections that were configured to use a TrustKit-provided `SSLSocketFactory` or `X509TrustManager`.
* The `SSLSocketFactory` or `X509TrustManager` provided by TrustKit can only be used for connections to the domain that was passed to the `getTrustManager()` and `getSSLSocketFactory()` methods. Hence, if a redirection to a different domain occurs, the new domain will fail SSL validation and the connection will fail. In practice, this should not be a problem because pinning validation is only meant to be used on the few specific domains on which the App's main server API is hosted --- redirections should not happen in this scenario.
* The `<trust-anchors>` setting is only applied when used within the global `<debug-overrides>` tag. Hence, custom trust anchors for specific domains cannot be set. 
* Within the `<trust-anchors>` tag, only `<certificate>` tags pointing to a raw certificate file are supported (the `user` or `system` values for the `src` attribute will be ignored).



License
-------

TrustKit Android is released under the MIT license. See LICENSE for details.
