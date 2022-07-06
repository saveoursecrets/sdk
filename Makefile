dev-certs:
	@cd sandbox && mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1
.PHONY: dev-certs

browser-gui:
	@rm -rf workspace/server/public
	@cd ../browser && make dist
	@cp -r ../browser/app/dist workspace/server/public
.PHONY: browser-gui

dev-server:
	@cd workspace/server && cargo run -- -c ../../sandbox/config.toml

server-release: browser-gui
	@cd workspace/server && cargo build --release
.PHONY: server-release

fmt:
	@cargo fmt --all
.PHONY: fmt

check:
	@cargo check --all
.PHONY: check

integration-test:
	@rm -rf target/integration-test
	@mkdir -p target/integration-test
	@cargo test
.PHONY: integration-test

unit-test:
	@cargo test --all --lib
.PHONY: unit-test

test: unit-test integration-test
.PHONY: test

dev: test fmt
.PHONY: dev

docs:
	@cargo doc --all --open --no-deps
.PHONY: docs
