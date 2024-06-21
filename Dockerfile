FROM rust:latest as builder

WORKDIR /usr/app

ENV CARGO_HOME /usr/app
ENV PATH="/usr/app/bin:${PATH}"

COPY sandbox/config.toml config.toml
RUN mkdir accounts
RUN cargo install --locked sos-server

CMD sos-server start /usr/app/config.toml
