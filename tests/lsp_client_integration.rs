mod common;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

use common::lsp_client::{path_to_file_uri, LspTestClient};

fn unique_temp_dir() -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_micros();
    let dir = std::env::temp_dir().join(format!("opforge-lsp-it-{now}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn unique_temp_file(name: &str) -> PathBuf {
    unique_temp_dir().join(name)
}

fn write_text(path: &PathBuf, text: &str) {
    fs::write(path, text).expect("write file");
}

fn write_executable_script(path: &PathBuf, script: &str) {
    fs::write(path, script).expect("write script");
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod script");
    }
}

fn init_with_validator(
    client: &mut LspTestClient,
    script: &PathBuf,
    debounce_ms: u64,
    on_save: bool,
) {
    let _ = client.initialize(json!({
        "opforgeLsp": {
            "opforgePath": script.to_string_lossy().to_string(),
            "validation": {
                "debounceMs": debounce_ms,
                "onSave": on_save
            }
        }
    }));
    client.notify("initialized", json!({}));
}

#[test]
fn initialize_reports_core_capabilities() {
    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let result = client.initialize(json!({}));
    let caps = result.get("capabilities").expect("capabilities");
    assert!(caps.get("completionProvider").is_some());
    assert!(caps.get("hoverProvider").is_some());
    assert!(caps.get("definitionProvider").is_some());
    assert!(caps.get("referencesProvider").is_some());
    assert!(caps.get("renameProvider").is_some());
    assert!(caps.get("documentSymbolProvider").is_some());
    assert!(caps.get("codeActionProvider").is_some());
    assert!(client
        .wait_for_notification("window/logMessage", Duration::from_millis(20))
        .is_none());
    client.shutdown();
}

#[test]
fn completion_uses_nearest_prior_cpu_context() {
    let temp_file = unique_temp_file("completion.asm");
    let uri = path_to_file_uri(&temp_file);
    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".cpu 6502\n    lda #$01\n.cpu z80\n    djnz target\n"
            }
        }),
    );

    let completion = client.request(
        "textDocument/completion",
        json!({
            "textDocument": {"uri": uri},
            "position": {"line": 3, "character": 8}
        }),
    );
    let items = completion.as_array().expect("completion array");
    assert!(
        items.iter().any(|item| {
            item.get("label")
                .and_then(|value| value.as_str())
                .is_some_and(|label| label.eq_ignore_ascii_case("djnz"))
        }),
        "expected z80 mnemonic suggestion at z80 context line"
    );

    client.shutdown();
}

#[test]
fn diagnostics_are_deduplicated_by_stable_key() {
    let temp_dir = unique_temp_dir();
    let script_path = temp_dir.join("validator.sh");
    write_executable_script(
        &script_path,
        r#"#!/bin/sh
set -eu
infile=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--infile" ]; then
    infile="$2"
    shift 2
    continue
  fi
  shift
done
printf '{"code":"E001","severity":"error","message":"dup","file":"%s","line":1,"col_start":1,"col_end":2,"fixits":[]}\n' "$infile"
printf '{"code":"E001","severity":"error","message":"dup","file":"%s","line":1,"col_start":1,"col_end":2,"fixits":[]}\n' "$infile"
"#,
    );

    let file = temp_dir.join("dedup.asm");
    write_text(&file, "nop\n");
    let uri = path_to_file_uri(&file);

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    init_with_validator(&mut client, &script_path, 0, true);
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": "nop\n"
            }
        }),
    );

    let publish = client
        .wait_for_publish_diagnostics(&uri, Duration::from_secs(2))
        .expect("publish diagnostics");
    let diagnostics = publish
        .get("diagnostics")
        .and_then(|value| value.as_array())
        .expect("diagnostics array");
    assert_eq!(
        diagnostics.len(),
        1,
        "duplicate diagnostics should be deduped"
    );
    client.shutdown();
}

#[test]
fn debounce_blocks_rapid_revalidation_but_allows_later_changes() {
    let temp_dir = unique_temp_dir();
    let script_path = temp_dir.join("validator.sh");
    write_executable_script(
        &script_path,
        r#"#!/bin/sh
set -eu
infile=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--infile" ]; then
    infile="$2"
    shift 2
    continue
  fi
  shift
done
printf '{"code":"EDEB","severity":"warning","message":"debounce","file":"%s","line":1,"col_start":1,"col_end":2,"fixits":[]}\n' "$infile"
"#,
    );

    let file = temp_dir.join("debounce.asm");
    write_text(&file, "nop\n");
    let uri = path_to_file_uri(&file);

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    init_with_validator(&mut client, &script_path, 3000, true);

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": "nop\n"
            }
        }),
    );
    let _ = client
        .wait_for_publish_diagnostics(&uri, Duration::from_secs(2))
        .expect("initial publish");

    client.notify(
        "textDocument/didChange",
        json!({
            "textDocument": {"uri": uri, "version": 2},
            "contentChanges": [{"text": "nop\n"}]
        }),
    );
    assert!(
        client
            .wait_for_publish_diagnostics(&uri, Duration::from_millis(150))
            .is_none(),
        "rapid didChange should be debounced"
    );

    thread::sleep(Duration::from_millis(3200));
    client.notify(
        "textDocument/didChange",
        json!({
            "textDocument": {"uri": uri, "version": 3},
            "contentChanges": [{"text": "nop\n"}]
        }),
    );
    assert!(
        client
            .wait_for_publish_diagnostics(&uri, Duration::from_secs(2))
            .is_some(),
        "later didChange should trigger validation after debounce window"
    );

    client.shutdown();
}

#[test]
fn on_save_forces_validation_even_when_change_is_debounced() {
    let temp_dir = unique_temp_dir();
    let script_path = temp_dir.join("validator.sh");
    write_executable_script(
        &script_path,
        r#"#!/bin/sh
set -eu
infile=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--infile" ]; then
    infile="$2"
    shift 2
    continue
  fi
  shift
done
printf '{"code":"ESAVE","severity":"error","message":"save-check","file":"%s","line":1,"col_start":1,"col_end":2,"fixits":[]}\n' "$infile"
"#,
    );

    let file = temp_dir.join("onsave.asm");
    write_text(&file, "nop\n");
    let uri = path_to_file_uri(&file);

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    init_with_validator(&mut client, &script_path, 5000, true);

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": "nop\n"
            }
        }),
    );
    let _ = client
        .wait_for_publish_diagnostics(&uri, Duration::from_secs(2))
        .expect("initial publish");

    client.notify(
        "textDocument/didChange",
        json!({
            "textDocument": {"uri": uri, "version": 2},
            "contentChanges": [{"text": "nop\n"}]
        }),
    );
    assert!(
        client
            .wait_for_publish_diagnostics(&uri, Duration::from_millis(150))
            .is_none(),
        "didChange should be debounced"
    );

    client.notify(
        "textDocument/didSave",
        json!({
            "textDocument": {"uri": uri},
            "text": "nop\n"
        }),
    );
    assert!(
        client
            .wait_for_publish_diagnostics(&uri, Duration::from_secs(2))
            .is_some(),
        "didSave should always trigger validation when onSave=true"
    );

    client.shutdown();
}

#[test]
fn overlay_remaps_dependency_diagnostics_to_original_uri() {
    let temp_dir = unique_temp_dir();
    let script_path = temp_dir.join("validator.sh");
    write_executable_script(
        &script_path,
        r#"#!/bin/sh
set -eu
infile=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--infile" ]; then
    infile="$2"
    shift 2
    continue
  fi
  shift
done
base="$(basename "$infile")"
if [ "$base" != "root.asm" ]; then
  exit 0
fi
dep="$(dirname "$infile")/helper.asm"
printf '{"code":"EDEP","severity":"error","message":"dependency-diagnostic","file":"%s","line":1,"col_start":1,"col_end":2,"fixits":[]}\n' "$dep"
"#,
    );

    let root_file = temp_dir.join("root.asm");
    let helper_file = temp_dir.join("helper.asm");
    write_text(&root_file, ".use helper\n");
    write_text(&helper_file, "value = 1\n");
    let root_uri = path_to_file_uri(&root_file);
    let helper_uri = path_to_file_uri(&helper_file);

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    init_with_validator(&mut client, &script_path, 0, true);

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": helper_uri,
                "version": 1,
                "languageId": "opforge",
                "text": "value = 2\n"
            }
        }),
    );
    let _ = client.wait_for_publish_diagnostics(&helper_uri, Duration::from_secs(1));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": root_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".use helper\n"
            }
        }),
    );

    let deadline = Instant::now() + Duration::from_secs(3);
    let dep_publish = loop {
        assert!(
            Instant::now() < deadline,
            "dependency diagnostics publish with EDEP was not observed"
        );
        let Some(candidate) =
            client.wait_for_publish_diagnostics(&helper_uri, Duration::from_millis(400))
        else {
            continue;
        };
        let diagnostics = candidate
            .get("diagnostics")
            .and_then(|value| value.as_array())
            .expect("diagnostics array");
        if diagnostics.iter().any(|diag| {
            diag.get("code")
                .and_then(|value| value.as_str())
                .is_some_and(|code| code == "EDEP")
        }) {
            break candidate;
        }
    };
    let diagnostics = dep_publish
        .get("diagnostics")
        .and_then(|value| value.as_array())
        .expect("diagnostics array");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0]
            .get("code")
            .and_then(|value| value.as_str())
            .unwrap_or_default(),
        "EDEP"
    );

    client.shutdown();
}

#[test]
fn definition_resolves_local_symbol_declaration() {
    let temp_file = unique_temp_file("definition.asm");
    let uri = path_to_file_uri(&temp_file);
    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": "label: nop\n    jmp label\n"
            }
        }),
    );

    let definitions = client.request(
        "textDocument/definition",
        json!({
            "textDocument": {"uri": uri},
            "position": {"line": 1, "character": 10}
        }),
    );
    let entries = definitions.as_array().expect("definition array");
    assert!(!entries.is_empty(), "expected at least one definition");
    let first = &entries[0];
    assert_eq!(
        first
            .get("uri")
            .and_then(|value| value.as_str())
            .unwrap_or_default(),
        uri
    );
    assert_eq!(
        first
            .get("range")
            .and_then(|range| range.get("start"))
            .and_then(|start| start.get("line"))
            .and_then(|line| line.as_u64())
            .unwrap_or(999),
        0
    );

    client.shutdown();
}

#[test]
fn definition_returns_deterministic_multi_results_for_module_targets() {
    let temp_dir = unique_temp_dir();
    let mods_a = temp_dir.join("a_mods");
    let mods_b = temp_dir.join("b_mods");
    fs::create_dir_all(&mods_a).expect("mods a");
    fs::create_dir_all(&mods_b).expect("mods b");
    write_text(&mods_a.join("math.asm"), "value = 1\n");
    write_text(&mods_b.join("math.inc"), "value = 2\n");

    let main = temp_dir.join("main.asm");
    write_text(&main, ".use math\n");
    let uri = path_to_file_uri(&main);

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({
        "opforgeLsp": {
            "modulePaths": [
                mods_b.to_string_lossy().to_string(),
                mods_a.to_string_lossy().to_string()
            ]
        }
    }));
    client.notify("initialized", json!({}));
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".use math\n"
            }
        }),
    );

    let first = client.request(
        "textDocument/definition",
        json!({
            "textDocument": {"uri": uri},
            "position": {"line": 0, "character": 6}
        }),
    );
    let second = client.request(
        "textDocument/definition",
        json!({
            "textDocument": {"uri": uri},
            "position": {"line": 0, "character": 6}
        }),
    );
    let first_items = first.as_array().expect("first definition array");
    let second_items = second.as_array().expect("second definition array");
    assert!(first_items.len() >= 2);
    assert_eq!(first_items.len(), second_items.len());
    let first_uris: Vec<String> = first_items
        .iter()
        .filter_map(|item| item.get("uri").and_then(|value| value.as_str()))
        .map(ToString::to_string)
        .collect();
    let second_uris: Vec<String> = second_items
        .iter()
        .filter_map(|item| item.get("uri").and_then(|value| value.as_str()))
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        first_uris, second_uris,
        "definition order must be deterministic"
    );
    assert_eq!(
        first_uris[0], uri,
        "local/module declaration should rank first"
    );
    let mut sorted = first_uris[1..].to_vec();
    sorted.sort();
    assert_eq!(
        first_uris[1..].to_vec(),
        sorted,
        "non-local candidates should use stable lexicographic order"
    );

    client.shutdown();
}

#[test]
fn code_actions_mark_machine_applicable_as_preferred() {
    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    let actions = client.request(
        "textDocument/codeAction",
        json!({
            "textDocument": {"uri": "file:///tmp/fixits.asm"},
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": 0, "character": 5}
            },
            "context": {
                "diagnostics": [{
                    "message": "missing endif",
                    "data": {
                        "fixits": [
                            {
                                "line": 1,
                                "col_start": 1,
                                "col_end": 1,
                                "replacement": ".endif",
                                "applicability": "machine-applicable"
                            },
                            {
                                "line": 1,
                                "col_start": 1,
                                "col_end": 1,
                                "replacement": ".endiff",
                                "applicability": "maybe-incorrect"
                            }
                        ]
                    }
                }]
            }
        }),
    );
    let entries = actions.as_array().expect("code action array");
    assert_eq!(entries.len(), 2);
    let preferred_count = entries
        .iter()
        .filter(|entry| {
            entry
                .get("isPreferred")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
        })
        .count();
    assert_eq!(preferred_count, 1);

    client.shutdown();
}

#[test]
fn hover_returns_semantic_symbol_metadata_for_assignments() {
    let temp_file = unique_temp_file("hover_semantic.asm");
    let uri = path_to_file_uri(&temp_file);
    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module math\nvalue = 42\n    lda value\n.endmodule\n"
            }
        }),
    );

    let hover = client.request(
        "textDocument/hover",
        json!({
            "textDocument": {"uri": uri},
            "position": {"line": 2, "character": 9}
        }),
    );
    let contents = hover
        .get("contents")
        .and_then(|value| value.get("value"))
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(contents.contains("Kind: `assignment`"));
    assert!(contents.contains("Scope: `module:math`"));
    assert!(contents.contains("Value: `42`"));
    assert!(contents.contains("Decl: `value = 42`"));

    client.shutdown();
}

#[test]
fn completion_includes_semantic_scope_detail_for_symbols() {
    let temp_file = unique_temp_file("completion_semantic.asm");
    let uri = path_to_file_uri(&temp_file);
    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module math\nvalue = 42\n    lda va\n.endmodule\n"
            }
        }),
    );

    let completion = client.request(
        "textDocument/completion",
        json!({
            "textDocument": {"uri": uri},
            "position": {"line": 2, "character": 10}
        }),
    );
    let items = completion.as_array().expect("completion array");
    let value_item = items.iter().find(|item| {
        item.get("label")
            .and_then(|value| value.as_str())
            .is_some_and(|label| label.eq_ignore_ascii_case("value"))
    });
    let value_item = value_item.expect("value symbol completion item");
    let detail = value_item
        .get("detail")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(detail.contains("assignment"));
    assert!(detail.contains("module:math"));

    client.shutdown();
}

#[test]
fn definition_resolves_imported_symbol_via_alias_qualified_reference() {
    let temp_dir = unique_temp_dir();
    let main_file = temp_dir.join("main.asm");
    let math_file = temp_dir.join("math.asm");
    let main_uri = path_to_file_uri(&main_file);
    let math_uri = path_to_file_uri(&math_file);

    write_text(
        &main_file,
        ".module app\n.use math as M\n    lda M.value\n.endmodule\n",
    );
    write_text(&math_file, ".module math\n.pub\nvalue = 42\n.endmodule\n");

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": math_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module math\n.pub\nvalue = 42\n.endmodule\n"
            }
        }),
    );
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": main_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module app\n.use math as M\n    lda M.value\n.endmodule\n"
            }
        }),
    );

    let defs = client.request(
        "textDocument/definition",
        json!({
            "textDocument": {"uri": main_uri},
            "position": {"line": 2, "character": 11}
        }),
    );
    let entries = defs.as_array().expect("definition array");
    assert!(
        !entries.is_empty(),
        "expected imported definition candidate"
    );
    assert_eq!(
        entries[0]
            .get("uri")
            .and_then(|value| value.as_str())
            .unwrap_or_default(),
        math_uri
    );
    assert_eq!(
        entries[0]
            .get("range")
            .and_then(|range| range.get("start"))
            .and_then(|start| start.get("line"))
            .and_then(|line| line.as_u64())
            .unwrap_or(999),
        2
    );

    client.shutdown();
}

#[test]
fn definition_prefers_local_symbol_over_imported_selective_alias() {
    let temp_dir = unique_temp_dir();
    let main_file = temp_dir.join("main.asm");
    let math_file = temp_dir.join("math.asm");
    let main_uri = path_to_file_uri(&main_file);
    let math_uri = path_to_file_uri(&math_file);

    write_text(
        &main_file,
        ".module app\n.use math (value as result)\nresult = 1\n    lda result\n.endmodule\n",
    );
    write_text(&math_file, ".module math\n.pub\nvalue = 42\n.endmodule\n");

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": math_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module math\n.pub\nvalue = 42\n.endmodule\n"
            }
        }),
    );
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": main_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module app\n.use math (value as result)\nresult = 1\n    lda result\n.endmodule\n"
            }
        }),
    );

    let defs = client.request(
        "textDocument/definition",
        json!({
            "textDocument": {"uri": main_uri},
            "position": {"line": 3, "character": 10}
        }),
    );
    let entries = defs.as_array().expect("definition array");
    assert!(!entries.is_empty(), "expected local definition candidate");
    assert_eq!(
        entries[0]
            .get("uri")
            .and_then(|value| value.as_str())
            .unwrap_or_default(),
        main_uri
    );
    assert_eq!(
        entries[0]
            .get("range")
            .and_then(|range| range.get("start"))
            .and_then(|start| start.get("line"))
            .and_then(|line| line.as_u64())
            .unwrap_or(999),
        2
    );

    client.shutdown();
}

#[test]
fn completion_and_hover_resolve_selective_import_alias_symbols() {
    let temp_dir = unique_temp_dir();
    let main_file = temp_dir.join("main.asm");
    let math_file = temp_dir.join("math.asm");
    let main_uri = path_to_file_uri(&main_file);
    let math_uri = path_to_file_uri(&math_file);

    write_text(
        &main_file,
        ".module app\n.use math (value as result)\n    lda res\n    lda result\n.endmodule\n",
    );
    write_text(&math_file, ".module math\n.pub\nvalue = 42\n.endmodule\n");

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": math_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module math\n.pub\nvalue = 42\n.endmodule\n"
            }
        }),
    );
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": main_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module app\n.use math (value as result)\n    lda res\n    lda result\n.endmodule\n"
            }
        }),
    );

    let completion = client.request(
        "textDocument/completion",
        json!({
            "textDocument": {"uri": main_uri},
            "position": {"line": 2, "character": 11}
        }),
    );
    let items = completion.as_array().expect("completion array");
    let imported = items.iter().find(|item| {
        item.get("label")
            .and_then(|value| value.as_str())
            .is_some_and(|label| label.eq_ignore_ascii_case("result"))
            && item
                .get("detail")
                .and_then(|value| value.as_str())
                .is_some_and(|detail| detail.contains("imported"))
    });
    assert!(
        imported.is_some(),
        "expected imported selective alias completion"
    );

    let hover = client.request(
        "textDocument/hover",
        json!({
            "textDocument": {"uri": main_uri},
            "position": {"line": 3, "character": 10}
        }),
    );
    let contents = hover
        .get("contents")
        .and_then(|value| value.get("value"))
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(contents.contains("Decl: `value = 42`"));
    assert!(contents.contains("Kind: `assignment`"));

    client.shutdown();
}

#[test]
fn workspace_symbol_supports_partial_query_with_stable_order() {
    let temp_dir = unique_temp_dir();
    let file_a = temp_dir.join("alpha.asm");
    let file_b = temp_dir.join("beta.asm");
    let uri_a = path_to_file_uri(&file_a);
    let uri_b = path_to_file_uri(&file_b);
    write_text(&file_a, ".module alpha\nvalueOne = 1\n.endmodule\n");
    write_text(&file_b, ".module beta\nvalueTwo = 2\n.endmodule\n");

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri_a,
                "version": 1,
                "languageId": "opforge",
                "text": ".module alpha\nvalueOne = 1\n.endmodule\n"
            }
        }),
    );
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri_b,
                "version": 1,
                "languageId": "opforge",
                "text": ".module beta\nvalueTwo = 2\n.endmodule\n"
            }
        }),
    );

    let first = client.request("workspace/symbol", json!({ "query": "value" }));
    let second = client.request("workspace/symbol", json!({ "query": "value" }));
    let first_items = first.as_array().expect("workspace symbol array");
    let second_items = second.as_array().expect("workspace symbol array");
    assert!(
        first_items.len() >= 2,
        "expected both value symbols to be returned"
    );
    assert_eq!(first_items.len(), second_items.len());

    let first_locations: Vec<String> = first_items
        .iter()
        .filter_map(|item| item.get("location"))
        .filter_map(|location| location.get("uri"))
        .filter_map(|uri| uri.as_str())
        .map(ToString::to_string)
        .collect();
    let second_locations: Vec<String> = second_items
        .iter()
        .filter_map(|item| item.get("location"))
        .filter_map(|location| location.get("uri"))
        .filter_map(|uri| uri.as_str())
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        first_locations, second_locations,
        "workspace symbol ordering must be deterministic"
    );

    let names: Vec<String> = first_items
        .iter()
        .filter_map(|item| item.get("name").and_then(|value| value.as_str()))
        .map(ToString::to_string)
        .collect();
    assert!(names
        .iter()
        .any(|name| name.eq_ignore_ascii_case("valueOne")));
    assert!(names
        .iter()
        .any(|name| name.eq_ignore_ascii_case("valueTwo")));

    client.shutdown();
}

#[test]
fn workspace_symbol_matches_substring_queries() {
    let temp_dir = unique_temp_dir();
    let file = temp_dir.join("substring.asm");
    let uri = path_to_file_uri(&file);
    write_text(
        &file,
        ".module search\nalphaValue = 1\nbetaThing = 2\n.endmodule\n",
    );

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module search\nalphaValue = 1\nbetaThing = 2\n.endmodule\n"
            }
        }),
    );

    let result = client.request("workspace/symbol", json!({ "query": "phaVal" }));
    let items = result.as_array().expect("workspace symbol array");
    assert!(
        items.iter().any(|item| {
            item.get("name")
                .and_then(|value| value.as_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("alphaValue"))
        }),
        "substring query should match alphaValue"
    );

    client.shutdown();
}

#[test]
fn overlapping_validations_publish_only_newest_version_results() {
    let temp_dir = unique_temp_dir();
    let script_path = temp_dir.join("validator.sh");
    write_executable_script(
        &script_path,
        r#"#!/bin/sh
set -eu
infile=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--infile" ]; then
    infile="$2"
    shift 2
    continue
  fi
  shift
done
if grep -q "slow-version" "$infile"; then
  sleep 1
  printf '{"code":"EOLD","severity":"warning","message":"stale","file":"%s","line":1,"col_start":1,"col_end":2,"fixits":[]}\n' "$infile"
  exit 0
fi
printf '{"code":"ENEW","severity":"warning","message":"fresh","file":"%s","line":1,"col_start":1,"col_end":2,"fixits":[]}\n' "$infile"
"#,
    );

    let file = temp_dir.join("cancel.asm");
    write_text(&file, "slow-version\n");
    let uri = path_to_file_uri(&file);

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    init_with_validator(&mut client, &script_path, 0, true);

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": "slow-version\n"
            }
        }),
    );
    thread::sleep(Duration::from_millis(80));

    client.notify(
        "textDocument/didChange",
        json!({
            "textDocument": {"uri": uri, "version": 2},
            "contentChanges": [{"text": "fast-version\n"}]
        }),
    );

    let publish = client
        .wait_for_publish_diagnostics(&uri, Duration::from_secs(3))
        .expect("newest diagnostics publish");
    let diagnostics = publish
        .get("diagnostics")
        .and_then(|value| value.as_array())
        .expect("diagnostics array");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0]
            .get("code")
            .and_then(|value| value.as_str())
            .unwrap_or_default(),
        "ENEW"
    );

    assert!(
        client
            .wait_for_publish_diagnostics(&uri, Duration::from_millis(1300))
            .is_none(),
        "stale slow validation result should be suppressed"
    );

    client.shutdown();
}

#[test]
fn references_return_local_declaration_and_uses() {
    let temp_file = unique_temp_file("references_local.asm");
    let uri = path_to_file_uri(&temp_file);
    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": "label: nop\n    jmp label\n    .word label\n"
            }
        }),
    );

    let refs = client.request(
        "textDocument/references",
        json!({
            "textDocument": {"uri": uri},
            "position": {"line": 1, "character": 10},
            "context": {"includeDeclaration": true}
        }),
    );
    let entries = refs.as_array().expect("references array");
    assert!(
        entries.len() >= 3,
        "expected declaration and both use references"
    );
    let lines: Vec<u64> = entries
        .iter()
        .filter_map(|entry| entry.get("range"))
        .filter_map(|range| range.get("start"))
        .filter_map(|start| start.get("line"))
        .filter_map(|line| line.as_u64())
        .collect();
    assert!(lines.contains(&0));
    assert!(lines.contains(&1));
    assert!(lines.contains(&2));

    client.shutdown();
}

#[test]
fn references_resolve_imported_alias_qualified_symbols() {
    let temp_dir = unique_temp_dir();
    let main_file = temp_dir.join("main.asm");
    let math_file = temp_dir.join("math.asm");
    let main_uri = path_to_file_uri(&main_file);
    let math_uri = path_to_file_uri(&math_file);
    write_text(
        &main_file,
        ".module app\n.use math as M\n    lda M.value\n    sta M.value\n.endmodule\n",
    );
    write_text(&math_file, ".module math\n.pub\nvalue = 42\n.endmodule\n");

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": math_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module math\n.pub\nvalue = 42\n.endmodule\n"
            }
        }),
    );
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": main_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module app\n.use math as M\n    lda M.value\n    sta M.value\n.endmodule\n"
            }
        }),
    );

    let refs = client.request(
        "textDocument/references",
        json!({
            "textDocument": {"uri": main_uri},
            "position": {"line": 2, "character": 11},
            "context": {"includeDeclaration": true}
        }),
    );
    let entries = refs.as_array().expect("references array");
    assert!(
        entries.len() >= 3,
        "expected imported declaration and two alias-qualified references"
    );
    let has_decl = entries.iter().any(|entry| {
        entry
            .get("uri")
            .and_then(|value| value.as_str())
            .is_some_and(|uri| uri == math_uri)
            && entry
                .get("range")
                .and_then(|range| range.get("start"))
                .and_then(|start| start.get("line"))
                .and_then(|line| line.as_u64())
                .is_some_and(|line| line == 2)
    });
    assert!(
        has_decl,
        "expected reference list to include imported declaration"
    );

    client.shutdown();
}

#[test]
fn rename_updates_local_declaration_and_references() {
    let temp_file = unique_temp_file("rename_local.asm");
    let uri = path_to_file_uri(&temp_file);
    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": "label: nop\n    jmp label\n    .word label\n"
            }
        }),
    );

    let result = client.request(
        "textDocument/rename",
        json!({
            "textDocument": {"uri": uri},
            "position": {"line": 1, "character": 10},
            "newName": "target"
        }),
    );

    let edits = result
        .get("changes")
        .and_then(|changes| changes.get(&uri))
        .and_then(|value| value.as_array())
        .expect("rename edits for local uri");
    assert!(edits.len() >= 3);
    assert!(edits.iter().all(|edit| {
        edit.get("newText")
            .and_then(|value| value.as_str())
            .is_some_and(|text| text == "target")
    }));

    client.shutdown();
}

#[test]
fn rename_updates_imported_declaration_and_alias_qualified_uses() {
    let temp_dir = unique_temp_dir();
    let main_file = temp_dir.join("main.asm");
    let math_file = temp_dir.join("math.asm");
    let main_uri = path_to_file_uri(&main_file);
    let math_uri = path_to_file_uri(&math_file);
    write_text(
        &main_file,
        ".module app\n.use math as M\n    lda M.value\n    sta M.value\n.endmodule\n",
    );
    write_text(&math_file, ".module math\n.pub\nvalue = 42\n.endmodule\n");

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": math_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module math\n.pub\nvalue = 42\n.endmodule\n"
            }
        }),
    );
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": main_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module app\n.use math as M\n    lda M.value\n    sta M.value\n.endmodule\n"
            }
        }),
    );

    let result = client.request(
        "textDocument/rename",
        json!({
            "textDocument": {"uri": main_uri},
            "position": {"line": 2, "character": 11},
            "newName": "count"
        }),
    );
    let changes = result.get("changes").expect("workspace edit changes");
    let math_edits = changes
        .get(&math_uri)
        .and_then(|value| value.as_array())
        .expect("rename edits for math module");
    assert!(math_edits.iter().any(|edit| {
        edit.get("newText")
            .and_then(|value| value.as_str())
            .is_some_and(|text| text == "count")
    }));

    let main_edits = changes
        .get(&main_uri)
        .and_then(|value| value.as_array())
        .expect("rename edits for main module");
    assert!(main_edits.iter().any(|edit| {
        edit.get("newText")
            .and_then(|value| value.as_str())
            .is_some_and(|text| text == "M.count")
    }));

    client.shutdown();
}

#[test]
fn prepare_rename_returns_leaf_span_for_alias_qualified_symbol() {
    let temp_dir = unique_temp_dir();
    let main_file = temp_dir.join("main.asm");
    let math_file = temp_dir.join("math.asm");
    let main_uri = path_to_file_uri(&main_file);
    let math_uri = path_to_file_uri(&math_file);
    write_text(
        &main_file,
        ".module app\n.use math as M\n    lda M.value\n.endmodule\n",
    );
    write_text(&math_file, ".module math\n.pub\nvalue = 42\n.endmodule\n");

    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": math_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module math\n.pub\nvalue = 42\n.endmodule\n"
            }
        }),
    );
    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": main_uri,
                "version": 1,
                "languageId": "opforge",
                "text": ".module app\n.use math as M\n    lda M.value\n.endmodule\n"
            }
        }),
    );

    let result = client.request(
        "textDocument/prepareRename",
        json!({
            "textDocument": {"uri": main_uri},
            "position": {"line": 2, "character": 11}
        }),
    );
    assert_eq!(
        result
            .get("placeholder")
            .and_then(|value| value.as_str())
            .unwrap_or_default(),
        "value"
    );
    let start_char = result
        .get("range")
        .and_then(|range| range.get("start"))
        .and_then(|start| start.get("character"))
        .and_then(|value| value.as_u64())
        .unwrap_or(999);
    let end_char = result
        .get("range")
        .and_then(|range| range.get("end"))
        .and_then(|end| end.get("character"))
        .and_then(|value| value.as_u64())
        .unwrap_or(999);
    assert_eq!(start_char, 10);
    assert_eq!(end_char, 15);

    client.shutdown();
}

#[test]
fn prepare_rename_returns_null_for_non_symbol_position() {
    let temp_file = unique_temp_file("prepare_rename_null.asm");
    let uri = path_to_file_uri(&temp_file);
    let mut client = LspTestClient::spawn().expect("spawn lsp");
    let _ = client.initialize(json!({}));
    client.notify("initialized", json!({}));

    client.notify(
        "textDocument/didOpen",
        json!({
            "textDocument": {
                "uri": uri,
                "version": 1,
                "languageId": "opforge",
                "text": "label: nop\n"
            }
        }),
    );

    let result = client.request(
        "textDocument/prepareRename",
        json!({
            "textDocument": {"uri": uri},
            "position": {"line": 0, "character": 5}
        }),
    );
    assert!(result.is_null(), "prepare rename should return null on ':'");

    client.shutdown();
}
