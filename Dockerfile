FROM rust:1.75-buster AS rust

WORKDIR /usr/app

COPY workspace workspace
COPY src src
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY sandbox/config.toml config.toml
RUN mkdir accounts
RUN cargo build --release --bin sos-server

CMD /usr/app/target/release/sos-server start /usr/app/config.toml
