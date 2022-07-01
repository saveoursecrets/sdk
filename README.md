# Secret Storage

A distributed, encrypted database with a focus on security, integrity and redundancy.

Used to store private secrets such as account passwords, notes, certificates and encryption keys.

## Server

The server requires TLS so a certificate and key file must be configured.

For local development use [mkcert][]:

```
mkcert -install
mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1
```

Then place the files next to the server configuration and update the `[tls]` section in the server configuration:

```toml
[tls]
cert = "cert.pem"
key = "key.pem"
```

Now you can start a development version of the server:

```
cd workspace/server
cargo run -- -c /path/to/config.toml
```

[mkcert]: https://github.com/FiloSottile/mkcert
