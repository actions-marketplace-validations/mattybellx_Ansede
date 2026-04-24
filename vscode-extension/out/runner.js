"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.runAnsedeScan = runAnsedeScan;
const child_process_1 = require("child_process");
const protocol_1 = require("./protocol");
function runAnsedeScan(options) {
    const timeoutMs = options.timeoutMs ?? 15000;
    return new Promise((resolve, reject) => {
        const child = (0, child_process_1.spawn)(options.executable, ['--stdin', '--lang', options.language, '--format', 'json', '--fail-on', 'never'], { windowsHide: true });
        let stdout = '';
        let stderr = '';
        let settled = false;
        const finish = (callback) => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(timer);
            callback();
        };
        const timer = setTimeout(() => {
            child.kill();
            finish(() => reject(new Error(`ansede-static timed out after ${timeoutMs}ms`)));
        }, timeoutMs);
        child.stdout.setEncoding('utf8');
        child.stderr.setEncoding('utf8');
        child.stdout.on('data', (chunk) => {
            stdout += chunk;
        });
        child.stderr.on('data', (chunk) => {
            stderr += chunk;
        });
        child.on('error', (error) => {
            finish(() => reject(error));
        });
        child.on('close', (code) => {
            finish(() => {
                if (!stdout.trim()) {
                    const detail = stderr.trim() || `ansede-static exited with code ${code ?? 'unknown'}`;
                    reject(new Error(detail));
                    return;
                }
                try {
                    resolve((0, protocol_1.parseReportPayload)(stdout));
                }
                catch (error) {
                    reject(error instanceof Error ? error : new Error(String(error)));
                }
            });
        });
        child.stdin.on('error', () => {
            // Ignore stdin shutdown races; close/error handlers above decide success.
        });
        child.stdin.end(options.code);
    });
}
//# sourceMappingURL=runner.js.map