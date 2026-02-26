// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::env;
use std::fs;
use std::path::PathBuf;

use opforge::core::registry::ModuleRegistry;
use opforge::families::intel8080::module::Intel8080FamilyModule;
use opforge::families::mos6502::module::{M6502CpuModule, MOS6502FamilyModule};
use opforge::i8085::module::I8085CpuModule;
use opforge::m45gs02::module::M45GS02CpuModule;
use opforge::m65816::module::M65816CpuModule;
use opforge::m65c02::module::M65C02CpuModule;
use opforge::vm::builder::build_hierarchy_package_from_registry;
use opforge::z80::module::Z80CpuModule;

fn default_registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    registry.register_family(Box::new(Intel8080FamilyModule));
    registry.register_family(Box::new(MOS6502FamilyModule));
    registry.register_cpu(Box::new(I8085CpuModule));
    registry.register_cpu(Box::new(Z80CpuModule));
    registry.register_cpu(Box::new(M6502CpuModule));
    registry.register_cpu(Box::new(M65C02CpuModule));
    registry.register_cpu(Box::new(M65816CpuModule));
    registry.register_cpu(Box::new(M45GS02CpuModule));
    registry
}

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

    let bytes = build_hierarchy_package_from_registry(&default_registry())?;
    fs::write(&output_path, &bytes)?;

    println!("wrote {} bytes to {}", bytes.len(), output_path.display());
    Ok(())
}
