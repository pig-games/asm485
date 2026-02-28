// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ValidationConfig {
    pub debounce_ms: u64,
    pub on_save: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            debounce_ms: 500,
            on_save: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LspConfig {
    pub roots: Vec<String>,
    pub include_paths: Vec<String>,
    pub module_paths: Vec<String>,
    pub defines: Vec<String>,
    pub default_cpu: Option<String>,
    pub opforge_path: Option<String>,
    pub validation: ValidationConfig,
}

impl LspConfig {
    pub fn update_from_workspace_settings(&mut self, settings: Option<&Value>) {
        let Some(settings) = settings else {
            return;
        };
        let Some(root) = settings.get("opforgeLsp") else {
            return;
        };

        if let Some(roots) = read_string_array(root.get("roots")) {
            self.roots = roots;
        }
        if let Some(paths) = read_string_array(root.get("includePaths")) {
            self.include_paths = paths;
        }
        if let Some(paths) = read_string_array(root.get("modulePaths")) {
            self.module_paths = paths;
        }
        if let Some(defines) = read_string_array(root.get("defines")) {
            self.defines = defines;
        }
        if let Some(cpu) = read_optional_string(root.get("defaultCpu")) {
            self.default_cpu = cpu;
        }
        if let Some(path) = read_optional_string(root.get("opforgePath")) {
            self.opforge_path = path;
        }
        if let Some(validation) = root.get("validation") {
            if let Some(ms) = validation.get("debounceMs").and_then(Value::as_u64) {
                self.validation.debounce_ms = ms.max(50);
            }
            if let Some(on_save) = validation.get("onSave").and_then(Value::as_bool) {
                self.validation.on_save = on_save;
            }
        }
    }
}

fn read_string_array(value: Option<&Value>) -> Option<Vec<String>> {
    value.and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect()
    })
}

fn read_optional_string(value: Option<&Value>) -> Option<Option<String>> {
    value.map(|v| v.as_str().map(ToString::to_string))
}
