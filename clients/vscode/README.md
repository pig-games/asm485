# opforge-lsp VS Code Reference Client

This folder contains a reference VS Code client for the `opforge-lsp` server.

## Development

1. Build the server:
   `cargo build --bin opforge-lsp`
2. Install extension dependencies:
   `npm install`
3. Compile extension:
   `npm run compile`
4. Launch an Extension Development Host from VS Code.

## Settings

The extension forwards these settings to the language server:

- `opforgeLsp.roots`
- `opforgeLsp.includePaths`
- `opforgeLsp.modulePaths`
- `opforgeLsp.defines`
- `opforgeLsp.defaultCpu`
- `opforgeLsp.validation.debounceMs`
- `opforgeLsp.validation.onSave`
- `opforgeLsp.opforgePath`
