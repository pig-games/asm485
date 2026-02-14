# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Erik van der Tier

.PHONY: build release clippy reference reference-test test test-opthread-runtime test-opthread-parity ci-opthread-mos6502 manual-pdf

MANUAL_MD := documentation/opForge-reference-manual.md
MANUAL_PDF := documentation/opForge-reference-manual.pdf

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

test-opthread-runtime:
	cargo test --features opthread-runtime opthread_runtime_mos6502_

test-opthread-parity:
	cargo test --features opthread-parity opthread_parity_smoke_instruction_bytes_and_diagnostics

ci-opthread-mos6502:
	make test
	make test-opthread-runtime
	make test-opthread-parity

reference-test:
	cargo test examples_match_reference_outputs

reference:
	opForge_UPDATE_REFERENCE=1 cargo test examples_match_reference_outputs -- --nocapture

manual-pdf:
	mkdir -p documentation
	pandoc $(MANUAL_MD) --from gfm --pdf-engine=xelatex -V geometry:margin=1in -V mainfont='Arial Unicode MS' -V sansfont='Arial' -V monofont='Menlo' -o $(MANUAL_PDF)
