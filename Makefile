all: wasm lint fmt check

wasm:
	@cd workspace/wasm && wasm-pack build --target=web

browser-gui:
	@rm -rf workspace/server/public
	@cd browser && yarn build
	@cp -r browser/dist workspace/server/public
	@rm -rf workspace/server/public/assets

server-release: browser-gui
	@cd workspace/server && cargo build --release

lint:
	@cd browser && yarn lint

fmt:
	@cd browser && yarn fmt
	@cargo fmt --all

check:
	@cargo check --all

test:
	@cargo test --all

docs:
	@cargo doc --all --open --no-deps

.PHONY: all wasm browser-gui fixtures server-release prettier lint fmt check test
