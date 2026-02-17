# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Erik van der Tier

.PHONY: build release clippy reference reference-test test test-opthread-runtime test-opthread-runtime-artifact test-opthread-runtime-intel test-opthread-rollout-criteria test-opthread-parity ci-opthread-mos6502 ci-opthread-intel8080 manual-pdf

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
	cargo test opthread_runtime_mos6502_

test-opthread-runtime-artifact:
	cargo test --features opthread-runtime-opcpu-artifact opthread_runtime_artifact_

test-opthread-runtime-intel:
	cargo test --features opthread-runtime-intel8080-scaffold opthread_runtime_intel8080_
	cargo test --features opthread-runtime-intel8080-scaffold opthread_runtime_intel8085_
	cargo test --features opthread-runtime-intel8080-scaffold opthread_runtime_z80_

test-opthread-rollout-criteria:
	cargo test opthread_rollout_criteria_

test-opthread-parity:
	cargo test --features opthread-parity opthread_parity_smoke_instruction_bytes_and_diagnostics

ci-opthread-mos6502:
	make test
	make test-opthread-runtime
	make test-opthread-runtime-artifact
	make test-opthread-rollout-criteria
	make test-opthread-parity

ci-opthread-intel8080:
	make test
	make test-opthread-rollout-criteria
	make test-opthread-runtime-intel

reference-test:
	cargo test examples_match_reference_outputs

reference:
	opForge_UPDATE_REFERENCE=1 cargo test examples_match_reference_outputs -- --nocapture

manual-pdf:
	mkdir -p documentation
	pandoc $(MANUAL_MD) --from gfm --pdf-engine=xelatex -V geometry:margin=1in -V mainfont='Arial Unicode MS' -V sansfont='Arial' -V monofont='Menlo' -o $(MANUAL_PDF)
