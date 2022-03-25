all: wasm lint fmt check

wasm:
	@cd workspace/wasm && wasm-pack build --target=web

browser-gui:
	@cd browser && yarn build

server-release: browser-gui
	@cd workspace/server && cargo build --release

prettier:
	@cd browser && yarn prettier

lint:
	@cd browser && yarn lint

fmt: prettier
	@cargo fmt --all

check:
	@cargo check --all

.PHONY: all wasm browser-gui server-release prettier lint fmt check
