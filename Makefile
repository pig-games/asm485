# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Erik van der Tier

.PHONY: build release clean fmt clippy audit reference reference-test test test-vm-runtime test-vm-runtime-artifact test-vm-runtime-intel test-vm-rollout-criteria test-vm-parity ci-vm-mos6502 ci-vm-intel8080 build-vm-package manual-pdf

MANUAL_MD := documentation/opForge-reference-manual.md
MANUAL_PDF := documentation/opForge-reference-manual.pdf

build:
	cargo clippy -- -D warnings
	cargo build

release:
	cargo clippy -- -D warnings
	cargo build --release

clean:
	cargo clean

fmt:
	cargo fmt --all

clippy:
	cargo clippy -- -D warnings

audit:
	cargo audit

test:
	cargo test

test-vm-runtime:
	cargo test vm_runtime_mos6502_

test-vm-runtime-artifact:
	cargo test --features vm-runtime-opcpu-artifact vm_runtime_artifact_

test-vm-runtime-intel:
	cargo test vm_runtime_intel8080_
	cargo test vm_runtime_intel8085_
	cargo test vm_runtime_z80_

test-vm-rollout-criteria:
	cargo test vm_rollout_criteria_

test-vm-parity:
	cargo test --features vm-parity vm_parity_smoke_instruction_bytes_and_diagnostics

ci-vm-mos6502:
	make test
	make test-vm-runtime
	make test-vm-runtime-artifact
	make test-vm-rollout-criteria
	make test-vm-parity

ci-vm-intel8080:
	make test
	make test-vm-rollout-criteria
	make test-vm-runtime-intel

build-vm-package:
	cargo run --bin build_vm_package -- target/vm/hierarchy.opcpu

reference-test:
	cargo test examples_match_reference_outputs

reference:
	opForge_UPDATE_REFERENCE=1 cargo test examples_match_reference_outputs -- --nocapture

manual-pdf:
	mkdir -p documentation
	pandoc $(MANUAL_MD) --from gfm --pdf-engine=xelatex -V geometry:margin=1in -V mainfont='Arial Unicode MS' -V sansfont='Arial' -V monofont='Menlo' -o $(MANUAL_PDF)
