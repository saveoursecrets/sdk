# Save Our Secrets SDK

> Save our Secrets (SOS) is a cross-platform, distributed, encrypted database with a focus on security, integrity and redundancy. It can be used to store private secrets such as account passwords, notes, certificates and encryption keys.

This repository contains the software development kit (SDK) and several command line interface (CLI) tools.

To see the code in action [download the app](https://saveoursecrets.com/#downloads).

See the [overview](/doc/overview.md) for concepts and terminology, the [API documentation for the SDK](https://docs.rs/sos-sdk/latest/sos_sdk/) or the [API documentation for the networking library](https://docs.rs/sos-net/latest/sos_net/) and check out the [sync protocol API types](https://docs.rs/sos-protocol/) for common networking code.

## Server

The server can be run using docker; account data is written to the `sandbox/accounts` directory:

```
docker compose up
```

To run a server that uses a certificate issued by the Let's Encrypt ACME service for TLS see the notes in [acme.toml](/sandbox/acme.toml).

### OpenAPI

Start a development server using the `sos-server` crate:

```
cargo run -p sos-server -- start sandbox/config.toml
```

Then browse the server [OpenAPI documentation](http://localhost:5053/api/v1/docs) or [download the JSON](http://localhost:5053/api/v1/docs/openapi.json).

## License

The server code is licensed under AGPL-3.0; other crates are licensed under the MIT or Apache-2.0 license at your discretion.

© Copyright Save Our Secrets Pte Ltd 2022-2024; all rights reserved.
