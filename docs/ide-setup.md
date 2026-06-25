# IDE Setup

## VS Code

### Install from Marketplace

1. Open VS Code
2. Go to Extensions (`Ctrl+Shift+X`)
3. Search for "Ansede Static Security Scanner"
4. Click Install

### Features

- Inline diagnostics for Python, JavaScript, TypeScript, Java, C#, Go
- Gutter decorations for findings
- Quick-fix suggestions via lightbulb
- Configurable severity threshold
- Scan on save, on type, or on open

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `ansede.enable` | `true` | Enable/disable inline scanning |
| `ansede.scanOnSave` | `true` | Re-scan on file save |
| `ansede.scanOnType` | `true` | Debounced re-scan while typing |
| `ansede.minSeverity` | `medium` | Minimum severity to show |
| `ansede.scanTimeoutMs` | `15000` | Per-file scan timeout |

### Commands

- `Ansede: Scan Current File` — scan the active editor file
- `Ansede: Scan Workspace` — scan the entire workspace

## IntelliJ IDEA

### Install

1. Download the plugin ZIP from [GitHub Releases](https://github.com/mattybellx/Ansede/releases)
2. In IntelliJ: `File → Settings → Plugins → ⚙ → Install Plugin from Disk...`
3. Select the downloaded ZIP

### Features

- Background file scanning in the IDE
- Inline annotations for detected vulnerabilities
- Configurable severity thresholds

## Visual Studio 2022

### Install

1. Download the VSIX from [GitHub Releases](https://github.com/mattybellx/Ansede/releases)
2. Run the VSIX installer or use `Extensions → Manage Extensions → Install from VSIX...`

### Features

- Solution-level scanning for C#, Python, JS/TS files
- Error List integration for findings
- Quick actions for auto-fix suggestions

## LSP Server

All three IDEs use the built-in LSP server under the hood. You can also connect manually:

```bash
ansede-static --lsp
```

This starts an LSP server on stdio following the LSP 3.18 protocol. Connect any LSP-capable editor by pointing it to:

```
ansede-static --lsp
```
