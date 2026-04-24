import * as vscode from 'vscode';

import { AnsedeFileResult, AnsedeFinding, countFindings } from './protocol';
import { runAnsedeScan } from './runner';


const SEVERITY_ORDER: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
};


function toDiagnosticSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'critical':
        case 'high':
            return vscode.DiagnosticSeverity.Error;
        case 'medium':
            return vscode.DiagnosticSeverity.Warning;
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}


function getLanguage(document: vscode.TextDocument): string | null {
    switch (document.languageId) {
        case 'python':
            return 'python';
        case 'javascript':
        case 'javascriptreact':
        case 'typescript':
        case 'typescriptreact':
            return 'javascript';
        default:
            return null;
    }
}


function diagnosticRange(document: vscode.TextDocument, finding: AnsedeFinding): vscode.Range {
    const lineNo = Math.max((finding.line ?? 1) - 1, 0);
    const safeLine = Math.min(lineNo, Math.max(document.lineCount - 1, 0));
    const line = document.lineAt(safeLine);
    return new vscode.Range(
        safeLine,
        line.firstNonWhitespaceCharacterIndex,
        safeLine,
        line.range.end.character,
    );
}


function parseErrorDiagnostic(message: string): vscode.Diagnostic {
    const range = new vscode.Range(new vscode.Position(0, 0), new vscode.Position(0, 0));
    const diagnostic = new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Warning);
    diagnostic.source = 'ansede-static';
    return diagnostic;
}


function pushFindingDiagnostics(
    document: vscode.TextDocument,
    result: AnsedeFileResult,
    minOrder: number,
    diagnostics: vscode.Diagnostic[],
): void {
    if (result.parse_error) {
        diagnostics.push(parseErrorDiagnostic(result.parse_error));
    }

    for (const finding of result.findings) {
        const order = SEVERITY_ORDER[finding.severity] ?? SEVERITY_ORDER.info;
        if (order > minOrder) {
            continue;
        }

        const parts: string[] = [finding.title];
        if (finding.description) {
            parts.push(finding.description);
        }
        if (finding.suggestion) {
            parts.push(`Fix: ${finding.suggestion}`);
        }
        if (finding.auto_fix) {
            parts.push(`\n${finding.auto_fix}`);
        }
        if (finding.rule_id) {
            parts.push(`Rule: ${finding.rule_id}`);
        }
        if (finding.analysis_kind) {
            parts.push(`Analysis: ${finding.analysis_kind}`);
        }
            if (typeof finding.confidence === 'number') {
                parts.push(`Confidence: ${finding.confidence.toFixed(2)}`);
            }

        const diagnostic = new vscode.Diagnostic(
            diagnosticRange(document, finding),
            parts.join('\n\n'),
            toDiagnosticSeverity(finding.severity),
        );
        diagnostic.source = 'ansede-static';
        const codeValue = finding.rule_id ?? finding.cwe;
        if (codeValue) {
            diagnostic.code = finding.cwe
                ? {
                    value: codeValue,
                    target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`),
                }
                : codeValue;
        }
        diagnostics.push(diagnostic);
    }
}


async function scanDocument(
    document: vscode.TextDocument,
    collection: vscode.DiagnosticCollection,
    statusItem: vscode.StatusBarItem,
): Promise<void> {
    const config = vscode.workspace.getConfiguration('ansede');
    if (!config.get<boolean>('enable', true)) {
        collection.delete(document.uri);
        statusItem.hide();
        return;
    }

    const language = getLanguage(document);
    if (!language) {
        return;
    }

    const minSeverity = config.get<string>('minSeverity', 'medium');
    const minOrder = SEVERITY_ORDER[minSeverity] ?? SEVERITY_ORDER.medium;
    const executable = config.get<string>('executable', 'ansede-static');

    statusItem.text = '$(shield~spin) Ansede scanning...';
    statusItem.tooltip = 'Ansede Static Security Scanner';
    statusItem.show();

    try {
        const report = await runAnsedeScan({
            executable,
            language,
            code: document.getText(),
            timeoutMs: 15_000,
        });

        const diagnostics: vscode.Diagnostic[] = [];
        for (const result of report.results) {
            pushFindingDiagnostics(document, result, minOrder, diagnostics);
        }
        collection.set(document.uri, diagnostics);

        const errorCount = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Error).length;
        const warningCount = diagnostics.filter(d => d.severity === vscode.DiagnosticSeverity.Warning).length;
        const totalFindings = countFindings(report);

        if (errorCount + warningCount === 0) {
            statusItem.text = totalFindings === 0 ? '$(shield) Ansede: clean' : '$(shield) Ansede: informational';
        } else {
            statusItem.text = `$(shield) Ansede: ${errorCount}E ${warningCount}W`;
        }
        statusItem.tooltip = `Ansede Static Security Scanner — ${totalFindings} finding(s) in latest scan`;
        statusItem.show();
    } catch (error) {
        collection.delete(document.uri);
        statusItem.text = '$(shield) Ansede: scan failed';
        statusItem.tooltip = error instanceof Error ? error.message : 'Ansede scan failed';
        statusItem.show();
    }
}


export function activate(context: vscode.ExtensionContext): void {
    const collection = vscode.languages.createDiagnosticCollection('ansede');
    const statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusItem.tooltip = 'Ansede Static Security Scanner';
    statusItem.command = 'ansede.scanCurrentFile';

    const scan = (document: vscode.TextDocument): Promise<void> => scanDocument(document, collection, statusItem);

    if (vscode.window.activeTextEditor) {
        void scan(vscode.window.activeTextEditor.document);
    }

    context.subscriptions.push(
        collection,
        statusItem,
        vscode.workspace.onDidOpenTextDocument(document => {
            void scan(document);
        }),
        vscode.workspace.onDidSaveTextDocument(document => {
            if (vscode.workspace.getConfiguration('ansede').get<boolean>('scanOnSave', true)) {
                void scan(document);
            }
        }),
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && vscode.workspace.getConfiguration('ansede').get<boolean>('scanOnOpen', true)) {
                void scan(editor.document);
            }
        }),
        vscode.commands.registerCommand('ansede.scanCurrentFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                void scan(editor.document);
            }
        }),
        vscode.commands.registerCommand('ansede.scanWorkspace', async () => {
            const folders = vscode.workspace.workspaceFolders;
            if (!folders) {
                return;
            }
            for (const folder of folders) {
                const files = await vscode.workspace.findFiles(
                    new vscode.RelativePattern(folder, '**/*.[pj]s'),
                    '**/node_modules/**',
                );
                for (const uri of files) {
                    const document = await vscode.workspace.openTextDocument(uri);
                    await scan(document);
                }
            }
            void vscode.window.showInformationMessage('Ansede: workspace scan complete. Check Problems panel.');
        }),
    );
}


export function deactivate(): void {}
