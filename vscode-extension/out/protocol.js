"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseReportPayload = parseReportPayload;
exports.countFindings = countFindings;
function parseReportPayload(stdout) {
    const parsed = JSON.parse(stdout);
    if (Array.isArray(parsed)) {
        return { results: parsed };
    }
    if (parsed && typeof parsed === 'object' && Array.isArray(parsed.results)) {
        return parsed;
    }
    return { results: [] };
}
function countFindings(report) {
    const summaryTotal = report.summary?.total_findings;
    if (typeof summaryTotal === 'number') {
        return summaryTotal;
    }
    return report.results.reduce((total, result) => total + result.findings.length, 0);
}
//# sourceMappingURL=protocol.js.map