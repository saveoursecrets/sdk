dev-certs:
	@cd sandbox && mkcert -key-file key.pem -cert-file cert.pem localhost 127.0.0.1 ::1
.PHONY: dev-certs

browser-gui:
	@rm -rf workspace/server/public
	@cd ../browser && make dist
	@cp -r ../browser/app/dist workspace/server/public
	@rm -rf workspace/server/public/assets
.PHONY: browser-gui

dev-server:
	@cd workspace/server && cargo run -- -c ../../sandbox/config.toml

server-release: browser-gui
	@cd workspace/server && cargo build --release
.PHONY: server-release

fmt:
	@cargo fmt --all
.PHONY: fmt

dev:
	@cargo test --all
	@cargo fmt --all
.PHONY: dev

check:
	@cargo check --all
.PHONY: check

test:
	@cargo test --all
.PHONY: test

docs:
	@cargo doc --all --open --no-deps
.PHONY: docs
