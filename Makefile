all: lint fmt check

browser-gui:
	@rm -rf workspace/server/public
	@cd ../browser/webapp && yarn build
	@cp -r ../browser/webapp/dist workspace/server/public
	@rm -rf workspace/server/public/assets

server-release: browser-gui
	@cd workspace/server && cargo build --release

fmt:
	@cargo fmt --all

dev:
	@cargo test --all
	@cargo fmt --all

check:
	@cargo check --all

test:
	@cargo test --all

docs:
	@cargo doc --all --open --no-deps

.PHONY: all browser-gui server-release prettier fmt check test
