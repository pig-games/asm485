# opThread VM Boundary & Protocol Specification (v1.0)

Status: active canonical spec  
Last updated: 2026-02-20

## 1. Purpose

This document normatively defines the host/VM boundary in opForge’s opThread integration.
It specifies:
- which responsibilities are host-owned vs VM-owned,
- where the host invokes VM contracts,
- strictness/fallback rules,
- rollout/override controls,
- and wire-level interaction patterns between host orchestration and VM runtime.

This specification reflects implemented behavior in:
- `src/assembler/mod.rs`
- `src/assembler/bootstrap.rs`
- `src/opthread/token_bridge.rs`
- `src/opthread/rollout.rs`

## 2. Scope

### 2.1 In scope
- Line-level assembly hot path: tokenization, parse envelope dispatch, expression parse/eval, instruction encode.
- Bootstrap path used before pass1/pass2: preprocessing, module graph loading, macro expansion, and module/use scanning.
- Runtime ownership precedence (`dialect -> cpu -> family`) and strictness behavior.
- Host override controls and their effects.

### 2.2 Out of scope
- CLI UX details unrelated to host/VM boundary semantics.
- Non-assembler tools that may consume `.opcpu` packages.
- Future full VM replacement of preprocessor/macro engines.

## 3. Canonical Boundary Matrix

| Stage | Owner | VM Used? | Normative Behavior |
|---|---|---|---|
| Preprocessor file expansion | Host | No | Host `Preprocessor` expands source/includes/defines before module graph assembly. |
| Module graph dependency traversal | Host | Yes (scanner) | Host builds graph/orchestration; line scans (`.module`, `.use`) parse via VM tokenizer/parser default model. |
| Macro expansion | Host | No (engine) | Host `MacroProcessor` performs expansion/injection; VM is not the macro executor. |
| Per-line tokenization in assembler passes | VM | Yes | `AsmLine::process_with_runtime_tokenizer` requires runtime model and uses VM tokenization path. |
| Per-line parser envelope | VM | Yes | `parse_line_with_model` validates PARS/PRVM contracts and executes parser VM. |
| Expression parse/eval on assembly hot path | VM by default | Yes | Certified families default to VM expression parser/eval; strict contract/version checks are errors. |
| Instruction candidate resolution/encode | VM-first with strictness | Yes | VM encode path is authoritative for certified families; contract failures are explicit errors. |
| Pass orchestration, symbols, image/list/map output | Host | No | Host controls pass loop, symbol lifecycle, listings/map/hex/bin I/O. |

## 4. High-Level Architecture

```mermaid
flowchart TD
	A[Source Files] --> B[Host Preprocessor]
	B --> C[Host Module Graph Builder]
	C --> D[Host Macro Expansion]
	D --> E[Expanded Lines]
	E --> F[Host Pass1/Pass2 Orchestration]

	subgraph VM_HOT_PATH[VM-Authoritative Line Hot Path]
	  T[VM Tokenizer] --> P[VM Parser Envelope]
	  P --> X[VM Expression Parse/Eval]
	  X --> I[VM Instruction/Directive Encode]
	end

	F --> T
	I --> G[Host Symbol/Image/LST/HEX/BIN/Map Outputs]
```

## 5. Bootstrap Protocol (Host-Orchestrated, VM-Assisted Scanning)

Bootstrap entry (`run_one`) performs:
1. host preprocess (`expand_source_file`),
2. host module graph load (`load_module_graph`),
3. pass1/pass2 orchestration.

Within module graph load, host scanners call `parse_line_with_default_model` for `.module` and `.use` extraction.

```mermaid
sequenceDiagram
	participant CLI as Host CLI
	participant ASM as Host Assembler(run_one)
	participant BOOT as Host Bootstrap
	participant VM as opThread VM tokenizer/parser bridge
	participant MP as Host MacroProcessor

	CLI->>ASM: run_one(input)
	ASM->>BOOT: expand_source_file(path, defines)
	BOOT-->>ASM: preprocessed root lines
	ASM->>BOOT: load_module_graph(root_lines)
	loop scan .module/.use
		BOOT->>VM: parse_line_with_default_model(line)
		VM-->>BOOT: LineAst or parse error
	end
	BOOT->>MP: expand deps/root with import visibility
	MP-->>BOOT: expanded lines
	BOOT-->>ASM: ModuleGraphResult{lines, module_macro_names}
```

Normative note:
- VM is a scanner/parser service here, not the owner of module graph or macro expansion orchestration.

## 6. Assembly Hot Path Protocol (Host ↔ VM)

For each line in pass1/pass2, host uses VM-first parse/expr/encode contracts.

```mermaid
sequenceDiagram
	participant H as Host AsmLine
	participant TB as Token Bridge
	participant M as HierarchyExecutionModel
	participant R as Runtime Contracts (TOKS/TKVM/PARS/PRVM/EXPR/TABL)

	H->>TB: parse_line_with_model(model, cpu, line)
	TB->>M: tokenize_portable_statement_for_assembler
	M->>R: resolve token policy + tokenizer VM
	R-->>M: portable tokens
	M-->>TB: core tokens + spans
	TB->>M: validate_parser_contract_for_assembler
	TB->>M: resolve_parser_vm_program
	TB->>M: execute parser VM envelope
	M-->>TB: LineAst
	TB-->>H: LineAst

	H->>M: encode_instruction_from_exprs / eval portable expr
	M->>R: resolve EXPR + TABL/MSEL/FORM by owner precedence
	R-->>M: bytes or deterministic error
	M-->>H: emitted bytes / error
```

## 7. Ownership and Precedence

All runtime-resolved contracts are owner-scoped and resolved with this precedence:
1. dialect
2. cpu
3. family

This precedence applies uniformly to tokenizer policy/programs, parser contracts/programs, expression contracts, and encode tables/selectors.

## 8. Strictness and Failure Rules

Normative rules:
- Unknown/mismatched VM opcode versions are hard errors.
- Missing required VM program/contract for authoritative path is a hard error.
- Invalid VM output shape (for example empty non-comment token stream where forbidden) is a hard error.
- VM contract/version failures are never interpreted as soft host fallback signals.

Determinism requirements:
- Budget ceilings and diagnostics are deterministic for repeated runs over identical inputs.

## 9. Rollout Defaults and Override Controls

### 9.1 Current defaults (v1, active)
- Runtime/package path: authoritative for `mos6502` and `intel8080` families.
- Expression eval path: authoritative for `mos6502` and `intel8080` families.
- Expression parser path: authoritative for `mos6502` and `intel8080` families.

### 9.2 Host override controls
Environment controls recognized by assembler runtime:
- `OPTHREAD_EXPR_EVAL_OPT_IN_FAMILIES`
- `OPTHREAD_EXPR_EVAL_FORCE_HOST_FAMILIES`

Rules:
- `FORCE_HOST` disables default expression VM eval for matching family ids.
- `OPT_IN` enables expression VM eval for staged families.
- If both apply, `FORCE_HOST` wins.

Boundary caveat:
- These controls affect expression eval gating only.
- They do not replace host orchestration responsibilities (preprocess/module graph/macro/output orchestration).

## 10. Explicit Host Responsibilities (Non-VM)

The following remain host-owned by specification:
- Filesystem and module discovery.
- Preprocessor include/define expansion.
- Macro expansion and import visibility injection.
- Pass1/pass2 scheduling and line traversal.
- Symbol table lifecycle + diagnostics aggregation.
- Artifact emission (`.lst`, `.hex`, `.bin`, map/export/link outputs).

## 11. Compliance Criteria

An implementation is compliant with this spec when:
- The line hot path uses VM tokenizer/parser/expr/encode for authoritative families.
- Host orchestration boundary remains explicit as defined in Sections 3/10.
- Runtime precedence is `dialect -> cpu -> family`.
- Contract and opcode compatibility checks are enforced at runtime.
- Deterministic limits and diagnostics are preserved.

## 12. Supersession

This document supersedes prior fragmented opThread VM boundary notes in `dev-docs/NextSteps`.

## Appendix A — Boundary Traceability Map (Rule → Code)

| Boundary Rule | Primary Entry Points | Notes |
|---|---|---|
| Host owns preprocess expansion | `assembler::bootstrap::expand_source_file` (`src/assembler/bootstrap.rs`) | Uses host `Preprocessor`; no VM tokenizer execution in this function. |
| Host owns module graph traversal | `assembler::bootstrap::load_module_graph` (`src/assembler/bootstrap.rs`) | Host recursion/order bookkeeping is authoritative. |
| Module/use scanning uses VM tokenizer/parser bridge | `assembler::bootstrap::parse_line_ast` → `opthread::token_bridge::parse_line_with_default_model` | VM is used as parser service for scanning, not for orchestration decisions. |
| Host owns macro expansion engine | `assembler::bootstrap::expand_with_processor` + `MacroProcessor::expand` | Expansion/injection semantics remain host-side. |
| Assembler line tokenization uses VM model | `AsmLine::process_with_runtime_tokenizer` (`src/assembler/mod.rs`) | Hard error if model missing on authoritative path. |
| Parser envelope is VM-driven | `opthread::token_bridge::parse_line_with_model` | Validates parser contract/program and executes parser VM envelope. |
| Runtime package defaults by family | `opthread::rollout::package_runtime_default_enabled_for_family` | Used to gate authoritative runtime path behavior. |
| Expr eval default/overrides | `opthread::rollout::portable_expr_runtime_enabled_for_family` + assembler env ingestion (`expr_eval_*_families_from_env`) | Supports default + opt-in + force-host precedence. |
| Expr parser default/overrides | `opthread::rollout::portable_expr_parser_runtime_enabled_for_family` | Family-level parser VM gating source of truth. |
| Force-host expression eval check in encode loop | `AsmLine::portable_expr_runtime_force_host_for_family` and call site in instruction path (`src/assembler/mod.rs`) | Explicit host override only for expression eval lane. |
| VM-first instruction encode path | `HierarchyExecutionModel::encode_instruction_from_exprs` call path from `AsmLine` instruction processing | Certified families treat VM encode output as authoritative. |
| Host owns pass orchestration and output emission | `run_one`, `Assembler::pass1`, `Assembler::pass2`, listing/hex/bin/map builders (`src/assembler/mod.rs`) | VM does not own filesystem outputs or pass scheduling. |

### A.1 Protocol hook summary

- **Bootstrap hook:** host scanning calls VM parser bridge through `parse_line_with_default_model`.
- **Hot-path hook:** per-line assembly goes through VM tokenizer/parser (`parse_line_with_model`) before AST execution.
- **Encode/eval hook:** instruction/directive expression handling delegates to runtime VM contracts based on rollout + override rules.
