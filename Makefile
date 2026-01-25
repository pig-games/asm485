.PHONY: build release clippy reference reference-test test

build:
	cargo clippy -- -D warnings
	cargo build

release:
	cargo clippy -- -D warnings
	cargo build --release

clippy:
	cargo clippy -- -D warnings

test:
	cargo test

reference-test:
	cargo test examples_match_reference_outputs

reference:
	ASM485_UPDATE_REFERENCE=1 cargo test examples_match_reference_outputs -- --nocapture
