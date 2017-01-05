# Getting Started

Adding TrustKit to an App can be achieved through the following steps:

1. Generating SSL pins for the App's server endpoints and choosing a pinning
policy.
2. Adding TrustKit as a dependency to the App.
3. Initializing TrustKit with the pinning policy.


## Warning

Public key pinning can be dangerous and requires more than just code-level
changes in your App. If you make a mistake, you might cause your App to pin a
set of keys that validates today but which stops validating a week or a year
from now, if something changes. In that case, your App will no longer be able to
connect to its servers and will most likely stop working, until it gets updated
with a new set of pins.

Unless you are confident that you understand the Web PKI that you can manage
the App servers' cryptographic identity very well, you should not use key
pinning.


## Generating SSL Pins

Before deploying SSL pinning within your App, you first need to investigate and
choose which domains and public keys need to be pinned. This is **very
important** as enabling the wrong pinning policy may prevent your App from being
able to connect to its servers, when the servers' keys are rotated.

The following blog post provides some information on which keys to pin and what
the trade-offs are:
[https://noncombatant.org/2015/05/01/about-http-public-key-pinning/](https://noncombatant.org/2015/05/01/about-http-public-key-pinning/).

In the context of TrustKit, an SSL pin is the base64-encoded SHA-256 of a
certificate's Subject Public Key Info; this is the same as what is described in
the [HTTP Public Key Pinning
specification](https://developer.mozilla.org/en-US/docs/Web/Security/Public_Key_Pinning).

To generate such values, a Python helper script is available within the [iOS project's 
repository](https://github.com/datatheorem/TrustKit); it can be used to generate the pin configuration from a PEM or DER 
certificate:

    $ python get_pin_from_certificate.py ca.pem
    $ python get_pin_from_certificate.py --type DER ca.der


## Deploying TrustKit

### Adding TrustKit as a Dependency

TrustKit Android can be deployed using Gradle, by adding this line to your _build.gradle_:

`compile 'com.datatheorem.truskit:trustkit-android:'`

### Configuring a Pinning Policy

Deploying SSL pinning in the App requires initializing TrustKit Android with a pinning policy (domains, pins, and additional settings). The policy is wrapped in the official [Android N Network Security Configuration](https://developer.android.com/training/articles/security-config.html) i.e :

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


#### Always start with pinning enforcement disabled

To avoid locking out too many users from your App when deploying SSL pinning
for the first time, it is advisable to set `enforcePinning` to `false`, so that SSL 
connections will succeed regardless of pin validation.


#### Always provide at least one backup pin

In order to prevent accidentally locking users out of your site, make sure you
have at least one backup pin and that you have procedures in place to
transition to using the backup pin if your primary pin can no longer be used.
For example, if you pin to the public key of your server's certificate, you
should generate a backup key that is stored somewhere safe. If you pin to an
intermediate CA or a root CA, then you should also select an alternative CA
that you are willing to switch to if your current CA (or their intermediate CA)
becomes invalid for some reason.

If you do not have a backup pin, you could inadvertently prevent your app from
working until you released a new version of your app, and your users updated
it. [One such
incident](https://cabforum.org/pipermail/public/2016-November/008989.html) led
to a bank having to ask their CA to issue a new certificate using a deprecated
intermediate CA in order to allow their users to use the app, or face weeks of
the app being unusable.


#### Deploy a reporting server or use Data Theorem's free server

Adding a report URL using the `<report-uri>` setting to receive pin validation 
failure reports will help track pin validation failures happening across your user 
base. You can use your own report server or Data Theorem's, which provides a 
dashboard to display these reports for free (email info@datatheorem.com for 
access).

This will give you an idea of how many users would be blocked, if pin validation 
was to be enforced.


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

Then, TrustKit Android should be initialized with the same path:

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
  super.OnCreate(savedInstanceState);

  // Using the default path - res/xml/network_security_config.xml
  TrustKit.initializeWithNetworkSecurityConfiguration(this);

  // OR using a custom resource (TrustKit can't be initialized twice)
  TrustKit.initializeWithNetworkSecurityConfiguration(this, R.id.my_custom_network_security_config);

  URL url = new URL("https://www.datatheorem.com");

  // HttpsUrlConnection
  HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
  connection.setSSLSocketFactory(new TrustKitSSLSocketFactory());

  // OkHttp 3
  OkHttpClient client =
    new OkHttpClient().newBuilder()
    .sslSocketFactory(new TrustKitSSLSocketFactory(),
                      TrustKit.getInstance().getTrustManager("www.datatheorem.com"))
    .build();
}
```

Once TrustKit Android has been initialized and the client or connection's `SSLSocketFactory` has been set, it will verify the server's certificate chain against the configured pinning policy whenever an HTTPS connection is initiated. If a report URI has been configured, the App will also send reports to the specified URI whenever a pin validation failure occurred.

