# Configurations files

## LibreSSL / OpenSSL 1.1+

You can now use ChaCha20 in addition to AES. Add this in your server block:

```nginx
ssl_ciphers EECDH+CHACHA20:EECDH+AESGCM:EECDH+AES;
```

You can also use more secure curves :

```nginx
ssl_ecdh_curve X25519:P-521:P-384:P-256;
```

## TLS 1.3

TLS 1.3 needs special ciphers.

```nginx
ssl_protocols TLSv1.3 TLSv1.2;
ssl_ciphers TLS-CHACHA20-POLY1305-SHA256:TLS-AES-256-GCM-SHA384:TLS-AES-128-GCM-SHA256:EECDH+CHACHA20:EECDH+AESGCM:EECDH+AES;
```

TLS- can be TLS13-.

## GeoIP 2

See https://github.com/leev/ngx_http_geoip2_module#example-usage


## ModSecurity

See this [tutorial](https://www.nginx.com/blog/compiling-and-installing-modsecurity-for-open-source-nginx/) for a rough overview on how to configure ModSecurity
