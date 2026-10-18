.PHONY: all build iso qemu test check fmt clippy clean

all: build

build:
	cargo xtask build

iso:
	cargo xtask iso

qemu:
	cargo xtask qemu

test:
	cargo xtask test

check:
	cargo check --all-targets

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets -- -D warnings

clean:
	cargo clean
