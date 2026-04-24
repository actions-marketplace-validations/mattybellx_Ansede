export interface AnsedeFinding {
    severity: string;
    title: string;
    description: string;
    line: number | null;
    suggestion: string;
    rule_id?: string;
    cwe: string;
    category?: string;
    confidence?: number;
    analysis_kind?: string;
    auto_fix?: string;
}

export interface AnsedeFileSummary {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
    total?: number;
}

export interface AnsedeFileResult {
    file?: string;
    file_path?: string;
    language: string;
    findings: AnsedeFinding[];
    parse_error?: string;
    summary?: AnsedeFileSummary;
}

export interface AnsedeReportSummary {
    files_scanned?: number;
    clean_files?: number;
    parse_errors?: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    info?: number;
    total_findings?: number;
}

export interface AnsedeReportEnvelope {
    schema_version?: string;
    tool?: string;
    version?: string;
    engine_version?: string;
    summary?: AnsedeReportSummary;
    results: AnsedeFileResult[];
}

export function parseReportPayload(stdout: string): AnsedeReportEnvelope {
    const parsed: unknown = JSON.parse(stdout);
    if (Array.isArray(parsed)) {
        return { results: parsed as AnsedeFileResult[] };
    }
    if (parsed && typeof parsed === 'object' && Array.isArray((parsed as AnsedeReportEnvelope).results)) {
        return parsed as AnsedeReportEnvelope;
    }
    return { results: [] };
}

export function countFindings(report: AnsedeReportEnvelope): number {
    const summaryTotal = report.summary?.total_findings;
    if (typeof summaryTotal === 'number') {
        return summaryTotal;
    }
    return report.results.reduce((total, result) => total + result.findings.length, 0);
}