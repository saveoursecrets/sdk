FROM rust:latest

WORKDIR /usr/app

COPY sandbox/config.toml config.toml
RUN mkdir accounts
RUN cargo install --locked sos-server

CMD /usr/app/target/release/sos-server start /usr/app/config.toml
