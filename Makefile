all: wasm lint fmt check

wasm:
	@cd workspace/wasm && wasm-pack build --target=web

browser-gui:
	@rm -rf workspace/server/public
	@cd browser && yarn build
	@cp -r browser/dist workspace/server/public
	@rm -rf workspace/server/public/assets

fixtures:
	@cd workspace/core && rm -f ./fixtures/fba77e3b-edd0-4849-a05f-dded6df31d22.vault
	@cd workspace/core && rm -f ./fixtures/6691de55-f499-4ed9-b72d-5631dbf1815c.vault
	@cd workspace/client && cat ../core/fixtures/passphrase.txt | cargo run -- create --uuid fba77e3b-edd0-4849-a05f-dded6df31d22 ../core/fixtures
	@cd workspace/client && cat ../core/fixtures/passphrase.txt | cargo run -- create --uuid 6691de55-f499-4ed9-b72d-5631dbf1815c ../core/fixtures

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
