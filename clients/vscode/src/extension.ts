import * as path from "path";
import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const serverPath = resolveServerPath(context);
  const serverOptions: ServerOptions = {
    run: {
      command: serverPath,
      transport: TransportKind.stdio,
    },
    debug: {
      command: serverPath,
      transport: TransportKind.stdio,
    },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "opforge" }],
    initializationOptions: buildInitializationOptions(),
    synchronize: {
      configurationSection: "opforgeLsp",
      fileEvents: vscode.workspace.createFileSystemWatcher("**/*.{asm,inc}"),
    },
  };

  client = new LanguageClient(
    "opforgeLsp",
    "opforge-lsp",
    serverOptions,
    clientOptions,
  );
  context.subscriptions.push(client.start());

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (!event.affectsConfiguration("opforgeLsp")) {
        return;
      }
      client
        ?.sendNotification("workspace/didChangeConfiguration", {
          settings: { opforgeLsp: buildInitializationOptions().opforgeLsp },
        })
        .then(
          () => undefined,
          () => undefined,
        );
    }),
  );
}

export async function deactivate(): Promise<void> {
  if (!client) {
    return;
  }
  await client.stop();
  client = undefined;
}

function buildInitializationOptions(): { opforgeLsp: Record<string, unknown> } {
  const config = vscode.workspace.getConfiguration("opforgeLsp");
  return {
    opforgeLsp: {
      roots: config.get<string[]>("roots", []),
      includePaths: config.get<string[]>("includePaths", []),
      modulePaths: config.get<string[]>("modulePaths", []),
      defines: config.get<string[]>("defines", []),
      defaultCpu: config.get<string | null>("defaultCpu", null),
      opforgePath: config.get<string | null>("opforgePath", null),
      validation: {
        debounceMs: config.get<number>("validation.debounceMs", 500),
        onSave: config.get<boolean>("validation.onSave", true),
      },
    },
  };
}

function resolveServerPath(context: vscode.ExtensionContext): string {
  const configured = vscode.workspace
    .getConfiguration("opforgeLsp")
    .get<string | null>("opforgePath", null);
  if (configured && configured.trim().length > 0) {
    return configured;
  }
  return context.asAbsolutePath(path.join("..", "..", "..", "target", "debug", "opforge-lsp"));
}
