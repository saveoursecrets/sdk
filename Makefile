all: release

SMOKE_TEST=target/smoke-test
SMOKE_NAME=mock
SMOKE_PRIVATE_KEY=$(SMOKE_TEST)/$(SMOKE_NAME).key.json
SMOKE_PUBLIC_KEY=$(SMOKE_TEST)/$(SMOKE_NAME).pub.json
SMOKE_JWT_KEYPAIR=$(SMOKE_TEST)/$(SMOKE_NAME).pem
SMOKE_VAULT=$(SMOKE_TEST)/$(SMOKE_NAME).sos3

smoke:
	@rm -rf $(SMOKE_TEST)
	@mkdir -p $(SMOKE_TEST)
	@cargo run -q -- new keypair $(SMOKE_NAME) $(SMOKE_TEST) 
	@cargo run -q -- new jwt $(SMOKE_NAME) $(SMOKE_TEST) 
	@cargo run -q -- new vault $(SMOKE_NAME) $(SMOKE_TEST) 
	@cargo run -q -- user add $(SMOKE_VAULT) $(SMOKE_PUBLIC_KEY) 
	@cargo run -q -- vault list --jwt=$(SMOKE_JWT_KEYPAIR) --auth=$(SMOKE_PRIVATE_KEY) $(SMOKE_VAULT)

release:
	@cargo build --release

dev: fmt check

check:
	@cargo check --all

fmt:
	@cargo fmt --all

.PHONY: all smoke release check fmt
