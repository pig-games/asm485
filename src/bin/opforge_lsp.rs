// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

fn main() -> Result<(), Box<dyn std::error::Error>> {
    opforge::lsp::protocol::run_stdio()?;
    Ok(())
}
