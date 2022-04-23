all: wasm lint fmt check

wasm:
	@cd workspace/wasm && wasm-pack build --target=web

browser-gui:
	@cd workspace/server && rm -rf public && mkdir public
	@cd browser && yarn build

fixtures:
	@cd workspace/core && rm -f ./fixtures/fba77e3b-edd0-4849-a05f-dded6df31d22.vault
	@cd workspace/cli && cat ../core/fixtures/passphrase.txt | cargo run -- new vault --uuid fba77e3b-edd0-4849-a05f-dded6df31d22 ../core/fixtures

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

test:
	@cargo test --all

.PHONY: all wasm browser-gui fixtures server-release prettier lint fmt check test
