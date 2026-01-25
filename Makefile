.PHONY: build release clippy reference

build:
	cargo clippy -- -D warnings
	cargo build

release:
	cargo clippy -- -D warnings
	cargo build --release

clippy:
	cargo clippy -- -D warnings

reference:
	ASM485_UPDATE_REFERENCE=1 cargo test examples_match_reference_outputs -- --nocapture
