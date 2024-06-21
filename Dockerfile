FROM rust:latest

WORKDIR /usr/app

COPY crates crates
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY sandbox/config.toml config.toml
RUN mkdir accounts
RUN cargo build --release --locked -p sos-server

CMD /usr/app/target/release/sos-server start /usr/app/config.toml
