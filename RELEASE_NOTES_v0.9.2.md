# opForge v0.9.2 Release Notes

## Scope

This release covers all changes since the 0.9.1 release creation commit
(`f21a627`), through `HEAD` on `main`.

Delta summary for `f21a627..HEAD`:

- 296 files changed
- 45,989 insertions(+)
- 13,507 deletions(-)

## Highlights

- Diagnostics V2 and fixit workflow expansion:
  - structured diagnostic codes/spans
  - rustc-style text diagnostics as default
  - JSON diagnostic/output format support
  - machine-applicable fixit planning/application + stale-source guards
  - deduplication and overlap protection for fixits
- VM/runtime hardening and modularization:
  - `opthread` surface renamed to `vm`
  - runtime/package/token-bridge module extraction and cleanup
  - expanded edge-case/property coverage for package/runtime/bridge behavior
- CLI and tooling improvements:
  - global output format selector and JSON reports
  - environment-variable backed CLI defaults
  - include/module search-root improvements
  - labels/dependencies/capabilities output coverage and compatibility improvements
- Directive and dialect fixit quality improvements:
  - broader typo alias recognition for common directive misspellings
  - expanded VM/native parity assertions for diagnostic payload shape
  - richer examples/reference fixtures for directive and dialect fixits

## Added

- New diagnostic and compatibility examples, including:
  - JSON output examples
  - missing-end and typo-fixit error examples
  - dialect-oriented fixit examples and matching `.err` references
- Additional directive typo aliases with machine-applicable fixits:
  - `.elsif`, `.elif`, `.elsfi`, `.elsefi`, `.esleif`
  - `.endsec`, `.endsect`, `.endsectio`
  - `.endmod`, `.endmodle`, `.endmoduel`
  - `.enidf`, `.endmatc`, `.endmach`
- Expanded VM/native diagnostic parity coverage for:
  - primary span/severity/code alignment
  - help/note/fixit payload parity
  - parser-error dialect-fixit parity

## Changed

- Listing headers now consistently derive version from crate metadata.
- README was updated with a dedicated diagnostics/fixits section and direct
  example → reference links.
- Docs and manual sections were synchronized with current diagnostics/CLI behavior.

## Fixed

- Environment-sensitive CLI test stability issues that could cause hanging test runs.
- Multi-error diagnostic accumulation and listing diagnostic rendering edge cases.
- ANSI/listing and reference output consistency issues across example fixtures.
- Dialect-fixit example cases to ensure they trigger intended `asm402` diagnostics.

## Validation

Validated via release gate workflow and full-suite runs during the release prep:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo audit`
- `make test`

## Upgrade Notes

- Crate version is now `0.9.2`.
- README release-notes link now targets `RELEASE_NOTES_v0.9.2.md`.
