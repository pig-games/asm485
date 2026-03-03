# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Erik van der Tier

.PHONY: build release clean fmt clippy audit reference reference-test test test-core test-vm-runtime test-vm-runtime-artifact test-vm-runtime-intel test-vm-rollout-criteria test-vm-parity test-vm-opcpu-modes ci-core ci-vm-mos6502 ci-vm-intel8080 build-vm-package build-vm-runtime-artifact vm-only-build vm-only-release vm-only-build-embedded vm-only-release-embedded vm-only-build-unbundled vm-only-release-unbundled vm-only-build-unbundled-artifact vm-only-release-unbundled-artifact manual-pdf

MANUAL_MD := documentation/opForge-reference-manual.md
MANUAL_PDF := documentation/opForge-reference-manual.pdf
VM_RUNTIME_ARTIFACT := target/vm/opforge-vm-runtime.opcpu

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
	../scripts/cleanup-build-artifacts.sh ..

test-core:
	cargo test --no-default-features
	../scripts/cleanup-build-artifacts.sh ..

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

ci-core:
	make test-core

ci-vm-mos6502:
	make test-core
	make test-vm-runtime
	make test-vm-runtime-artifact
	make test-vm-rollout-criteria
	make test-vm-parity

ci-vm-intel8080:
	make test-core
	make test-vm-rollout-criteria
	make test-vm-runtime-intel

build-vm-package:
	cargo run --bin build_vm_package -- target/vm/hierarchy.opcpu

build-vm-runtime-artifact:
	cargo run --bin build_vm_package -- $(VM_RUNTIME_ARTIFACT)

vm-only-build: build-vm-runtime-artifact
	cargo build --features vm-runtime-only,vm-runtime-opcpu-artifact

vm-only-release: build-vm-runtime-artifact
	cargo build --release --features vm-runtime-only,vm-runtime-opcpu-artifact

vm-only-build-embedded:
	cargo build --features vm-runtime-only

vm-only-release-embedded:
	cargo build --release --features vm-runtime-only

vm-only-build-unbundled:
	cargo build --features vm-runtime-only,vm-runtime-opcpu-unbundled

vm-only-release-unbundled:
	cargo build --release --features vm-runtime-only,vm-runtime-opcpu-unbundled

vm-only-build-unbundled-artifact: build-vm-runtime-artifact
	cargo build --features vm-runtime-only,vm-runtime-opcpu-unbundled,vm-runtime-opcpu-artifact

vm-only-release-unbundled-artifact: build-vm-runtime-artifact
	cargo build --release --features vm-runtime-only,vm-runtime-opcpu-unbundled,vm-runtime-opcpu-artifact

test-vm-opcpu-modes:
	$(MAKE) vm-only-build-embedded
	target/debug/opforge --print-cpusupport >/dev/null
	$(MAKE) vm-only-build-unbundled
	@if target/debug/opforge -i examples/6502_simple.asm -l >/dev/null 2>&1; then \
		echo "expected vm-only unbundled run without package to fail"; \
		exit 1; \
	fi
	$(MAKE) build-vm-runtime-artifact
	target/debug/opforge --opcpu-package $(VM_RUNTIME_ARTIFACT) -i examples/6502_simple.asm -l >/dev/null
	$(MAKE) vm-only-build-unbundled-artifact
	target/debug/opforge -i examples/6502_simple.asm -l >/dev/null

reference-test:
	cargo test examples_match_reference_outputs
	../scripts/cleanup-build-artifacts.sh ..

reference:
	opForge_UPDATE_REFERENCE=1 cargo test examples_match_reference_outputs -- --nocapture

manual-pdf:
	mkdir -p documentation
	pandoc $(MANUAL_MD) --from gfm --pdf-engine=xelatex -V geometry:margin=1in -V mainfont='Arial Unicode MS' -V sansfont='Arial' -V monofont='Menlo' -o $(MANUAL_PDF)
