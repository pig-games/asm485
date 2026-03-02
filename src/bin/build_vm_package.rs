// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::env;
use std::fs;
use std::path::PathBuf;

use opforge::vm::builder::build_hierarchy_package_from_registry;

fn artifact_path_from_args() -> PathBuf {
    let mut args = env::args().skip(1);
    if let Some(path) = args.next() {
        PathBuf::from(path)
    } else {
        PathBuf::from("target/vm/hierarchy.opcpu")
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output_path = artifact_path_from_args();
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let bytes = build_hierarchy_package_from_registry(&opforge::build_default_registry())?;
    fs::write(&output_path, &bytes)?;

    println!("wrote {} bytes to {}", bytes.len(), output_path.display());
    Ok(())
}
