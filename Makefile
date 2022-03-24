all: wasm lint fmt check

wasm:
	@cd workspace/wasm && wasm-pack build --target=web

prettier:
	@cd browser && yarn prettier

lint:
	@cd browser && yarn lint

fmt: prettier
	@cargo fmt --all

check:
	@cargo check --all

.PHONY: all wasm prettier lint fmt check
