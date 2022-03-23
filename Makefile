wasm:
	@cd workspace/wasm && wasm-pack build --target=web

prettier:
	@cd browser && yarn prettier

fmt: prettier
	@cargo fmt --all

check:
	@cargo check --all

.PHONY: prettier fmt check wasm
