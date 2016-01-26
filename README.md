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

Example
---
Here's an example that uses a very simple HTTPS server in python, and the reports generated using the excellent [cipherscan](https://github.com/jvehent/cipherscan) tool with various sanetls options:

```
$ cat SimpleHTTPSServer.py
import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('localhost', 4443), SimpleHTTPServer.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
$ python SimpleHTTPSServer.py &
$ ./analyze.py -t localhost:4443
Warning: target is not a FQDN. SNI was disabled. Use a FQDN or '-servername <fqdn>'
localhost:4443 has bad ssl/tls

Things that are bad:
* remove cipher ECDHE-RSA-RC4-SHA
* remove cipher RC4-SHA
* don't use an untrusted or self-signed certificate

Changes needed to match the old level:
* remove cipher ECDHE-RSA-RC4-SHA
* remove cipher RC4-SHA
* consider enabling SSLv3
* use a certificate with sha1WithRSAEncryption signature
* consider enabling OCSP Stapling
* enforce server side ordering

Changes needed to match the intermediate level:
* remove cipher ECDHE-RSA-RC4-SHA
* remove cipher RC4-SHA
* consider enabling OCSP Stapling
* enforce server side ordering

Changes needed to match the modern level:
* remove cipher AES256-GCM-SHA384
* remove cipher AES256-SHA256
* remove cipher AES256-SHA
* remove cipher CAMELLIA256-SHA
* remove cipher AES128-GCM-SHA256
* remove cipher AES128-SHA256
* remove cipher AES128-SHA
* remove cipher CAMELLIA128-SHA
* remove cipher ECDHE-RSA-RC4-SHA
* remove cipher RC4-SHA
* remove cipher ECDHE-RSA-DES-CBC3-SHA
* remove cipher DES-CBC3-SHA
* disable TLSv1
* consider enabling OCSP Stapling
* enforce server side ordering
$ kill %1
[1]+  Terminated              python SimpleHTTPSServer.py &
$ sanetls -c HIGH python SimpleHTTPSServer.py &
$ $ ./analyze.py -t localhost:4443
Warning: target is not a FQDN. SNI was disabled. Use a FQDN or '-servername <fqdn>'
localhost:4443 has bad ssl/tls

Things that are bad:
* remove cipher AECDH-AES256-SHA
* remove cipher AECDH-AES128-SHA
* remove cipher AECDH-DES-CBC3-SHA
* don't use a public key smaller than 2048 bits
* don't use an untrusted or self-signed certificate

Changes needed to match the old level:
* remove cipher AECDH-AES256-SHA
* remove cipher AECDH-AES128-SHA
* remove cipher AECDH-DES-CBC3-SHA
* consider enabling SSLv3
* use a certificate with sha1WithRSAEncryption signature
* consider enabling OCSP Stapling
* enforce server side ordering

Changes needed to match the intermediate level:
* remove cipher AECDH-AES256-SHA
* remove cipher AECDH-AES128-SHA
* remove cipher AECDH-DES-CBC3-SHA
* consider using a SHA-256 certificate
* consider enabling OCSP Stapling
* enforce server side ordering

Changes needed to match the modern level:
* remove cipher AECDH-AES256-SHA
* remove cipher AECDH-AES128-SHA
* remove cipher AECDH-DES-CBC3-SHA
* remove cipher AES256-GCM-SHA384
* remove cipher AES256-SHA256
* remove cipher AES256-SHA
* remove cipher CAMELLIA256-SHA
* remove cipher AES128-GCM-SHA256
* remove cipher AES128-SHA256
* remove cipher AES128-SHA
* remove cipher CAMELLIA128-SHA
* remove cipher ECDHE-RSA-DES-CBC3-SHA
* remove cipher DES-CBC3-SHA
* disable TLSv1
* use a SHA-256 certificate
* consider enabling OCSP Stapling
* enforce server side ordering
$ kill %1
[1]+  Terminated              sanetls -c HIGH python SimpleHTTPSServer.py &
$ sanetls -c 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK' python SimpleHTTPSServer.py &
$ ./analyze.py -t localhost:4443
Warning: target is not a FQDN. SNI was disabled. Use a FQDN or '-servername <fqdn>'
localhost:4443 has bad ssl/tls

Things that are bad:
* don't use an untrusted or self-signed certificate

Changes needed to match the old level:
* consider enabling SSLv3
* add cipher DES-CBC3-SHA
* use a certificate with sha1WithRSAEncryption signature
* consider enabling OCSP Stapling
* enforce server side ordering

Changes needed to match the intermediate level:
* add cipher AES128-SHA
* consider enabling OCSP Stapling
* enforce server side ordering

Changes needed to match the modern level:
* disable TLSv1
* consider enabling OCSP Stapling
* enforce server side ordering
$
```

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
