# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Erik van der Tier

.PHONY: build release clippy reference reference-test test manual-pdf

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

reference-test:
	cargo test examples_match_reference_outputs

reference:
	opForge_UPDATE_REFERENCE=1 cargo test examples_match_reference_outputs -- --nocapture

manual-pdf:
	mkdir -p documentation
	pandoc $(MANUAL_MD) --from gfm --pdf-engine=xelatex -V geometry:margin=1in -V mainfont='Arial Unicode MS' -V sansfont='Arial' -V monofont='Menlo' -o $(MANUAL_PDF)
