Sane TLS
===
Inject sane configuration into any application that dynamically links against OpenSSL.

Why
---
QT doesn't have a way to set a minimum protocol version or blacklist protocols, only stopped considering vanilla SSLv3 as a SecureProtocol from QT 5.4 onwards, and still doesn't have a way of specifying DH parameters.

SaneTLS works around this by injecting configuration code in front of calls to OpenSSL. While designed with QT applications in mind, this should theoretically work for any application that dynamically links against OpenSSL.

Installation
---
```
make
sudo make install / checkinstall
```

Usage
---
```
sanetls [OPTION]... program [PROGRAM-OPTIONS]...

  -o, --options
                 Force the specified OpenSSL protocol options to always be set in the application.
  -d, --disableoptions
                 Force the specified OpenSSL protocol options to never be set in the application, unless present with --disableoptions, which takes precedence.
  -p, --dhparams
                 Force the application to use the specified dhparams file.
  -c, --ciphers
                 Force the application to use the specified OpenSSL cipher string.
```

For example, `sanetls quasselcore` will run `quasselcore` with SSLv3 disabled.


Caveats
---
Will not enforce limits where an application specifically requests a protocol method or cipher via eg. SSLv3_server_method.

Under the hood
---
 - If FORCED_OPTIONS is defined, ensures the specified options are always set. Currently defaults to SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_SINGLE_DH_USE.
 - If FORCED_CLEAROPTIONS is defined, ensures the specified options are not set, unless also present in FORCED_OPTIONS, which takes precedence. Currently defaults to SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION.
 - If DHPARAMS_FILE is defined, ensures dhparams are set and loaded from the specified file.
 - If FORCED_CIPHERS is defined, ensures the specified cipher string is used.

This interposer is designed to override configuration options. If a service provides conflicting configuration, it may not be respected!


TODO
---
 - Enforce SSL renegotiation limits for long running connections?
 - Warn if specific requests for deprecated or insecure mechanisms are used?
