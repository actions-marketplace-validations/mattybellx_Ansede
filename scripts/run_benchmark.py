from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_REPOS = [
    "https://github.com/apache/airflow.git",
    "https://github.com/getsentry/sentry.git",
    "https://github.com/pallets/flask.git",
    "https://github.com/tiangolo/fastapi.git",
]


DEFAULT_MANIFEST = "benchmarks/external_manifest.json"


@dataclass
class RepoMetric:
    repo: str
    files_scanned: int
    findings: int


@dataclass
class CaseMetric:
    case_id: str
    findings: int
    files_scanned: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float | None
    recall: float | None
    f1_score: float | None


def _safe_float(num: float, den: float) -> float | None:
    if den <= 0:
        return None
    return num / den


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or (precision + recall) == 0:
        return None
    return 2 * precision * recall / (precision + recall)


def _normalize_report_path(file_path: str, scan_root: Path) -> str:
    """Normalize finding file paths to stable POSIX-like project-relative form."""
    raw = str(file_path or "").strip()
    if not raw:
        return ""
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(scan_root.resolve()).as_posix()
        except (OSError, RuntimeError, ValueError):
            return candidate.as_posix()
    return candidate.as_posix().lstrip("./")


def _parse_spec(spec: dict[str, Any], scan_root: Path) -> tuple[str, int | None, str, str]:
    expected_path = _normalize_report_path(str(spec.get("path") or ""), scan_root)
    expected_rule = str(spec.get("rule_id") or "").strip()
    expected_cwe = str(spec.get("cwe") or "").strip().upper()
    line_raw = spec.get("line")
    try:
        expected_line = int(line_raw) if line_raw is not None else None
    except (TypeError, ValueError):
        expected_line = None
    return expected_path, expected_line, expected_rule, expected_cwe


def _spec_matches_signature(
    spec_values: tuple[str, int | None, str, str],
    signature: tuple[str, int | None, str, str],
) -> bool:
    expected_path, expected_line, expected_rule, expected_cwe = spec_values
    det_path, det_line, det_rule, det_cwe = signature
    if expected_path and det_path != expected_path:
        return False
    if expected_line is not None and det_line != expected_line:
        return False
    if expected_rule and det_rule != expected_rule:
        return False
    if expected_cwe and det_cwe != expected_cwe:
        return False
    return True


def _collect_detected_signatures(payload: dict[str, Any], scan_root: Path) -> set[tuple[str, int | None, str, str]]:
    """Collect granular finding signatures: (path, line, rule_id, cwe)."""
    signatures: set[tuple[str, int | None, str, str]] = set()
    for result in payload.get("results", []):
        if not isinstance(result, dict):
            continue
        result_path = _normalize_report_path(str(result.get("file_path") or ""), scan_root)
        for finding in result.get("findings", []):
            if not isinstance(finding, dict):
                continue
            line_raw = finding.get("line")
            try:
                line_value = int(line_raw) if line_raw is not None else None
            except (TypeError, ValueError):
                line_value = None
            rule_id = str(finding.get("rule_id") or "").strip()
            cwe = str(finding.get("cwe") or "").strip().upper()
            signatures.add((result_path, line_value, rule_id, cwe))
    return signatures


def _match_finding_specs(
    specs: list[dict[str, Any]],
    detected: set[tuple[str, int | None, str, str]],
    scan_root: Path,
) -> tuple[int, int]:
    """Match expected/forbidden finding specs against detected signatures.

    A spec matches when all explicitly-provided keys agree: path, line, rule_id, cwe.
    Returns (matched_count, missing_count).
    """
    matched = 0
    missing = 0
    for spec in specs:
        if not isinstance(spec, dict):
            continue
        spec_values = _parse_spec(spec, scan_root)
        is_match = any(_spec_matches_signature(spec_values, signature) for signature in detected)

        if is_match:
            matched += 1
        else:
            missing += 1
    return matched, missing


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True, check=False)


def _scan_repo(repo_path: Path, output_file: Path) -> RepoMetric:
    proc = _run([
        "python",
        "-m",
        "ansede_static.cli",
        str(repo_path),
        "--format",
        "json",
        "--output",
        str(output_file),
        "--fail-on",
        "never",
    ])
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"Scan failed for {repo_path}: {proc.stderr.strip()}")

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    summary = payload.get("summary", {}) if isinstance(payload, dict) else {}
    return RepoMetric(
        repo=repo_path.name,
        files_scanned=int(summary.get("files_scanned", 0) or 0),
        findings=int(summary.get("total_findings", 0) or 0),
    )


def _scan_payload(target_path: Path, output_file: Path, *, js_backend: str | None = None) -> dict[str, Any]:
    cmd = [
        "python",
        "-m",
        "ansede_static.cli",
        str(target_path),
        "--format",
        "json",
        "--output",
        str(output_file),
        "--fail-on",
        "never",
    ]
    if js_backend:
        cmd.extend(["--js-backend", js_backend])
    proc = _run(cmd)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"Scan failed for {target_path}: {proc.stderr.strip()}")
    return json.loads(output_file.read_text(encoding="utf-8"))


def _collect_detected_sets(payload: dict[str, Any]) -> tuple[set[str], set[str], int, int]:
    rule_ids: set[str] = set()
    cwes: set[str] = set()
    findings = 0
    files_scanned = int((payload.get("summary") or {}).get("files_scanned", 0) or 0)
    for result in payload.get("results", []):
        if not isinstance(result, dict):
            continue
        for finding in result.get("findings", []):
            if not isinstance(finding, dict):
                continue
            findings += 1
            rid = str(finding.get("rule_id") or "").strip()
            cwe = str(finding.get("cwe") or "").strip().upper()
            if rid:
                rule_ids.add(rid)
            if cwe:
                cwes.add(cwe)
    return rule_ids, cwes, findings, files_scanned


def _clone_source(entry: dict[str, Any], workspace: Path, *, branch: str) -> Path | None:
    source = entry.get("source")
    if not isinstance(source, dict):
        # Local case
        local_path = entry.get("path")
        if isinstance(local_path, str) and local_path.strip():
            candidate = (Path.cwd() / local_path).resolve()
            return candidate if candidate.exists() else None
        return None

    repo = str(source.get("repo") or "").strip()
    if not repo:
        return None
    ref = str(source.get("ref") or branch).strip() or branch
    name = repo.rsplit("/", 1)[-1].removesuffix(".git")
    dest = workspace / name
    clone = _run(["git", "clone", "--depth", "1", "--branch", ref, repo, str(dest)])
    if clone.returncode != 0:
        clone = _run(["git", "clone", "--depth", "1", repo, str(dest)])
    if clone.returncode != 0:
        return None

    subdir = str(source.get("subdir") or "").strip()
    if subdir:
        scoped = (dest / subdir).resolve()
        return scoped if scoped.exists() else dest
    return dest


def _evaluate_manifest_case(entry: dict[str, Any], workspace: Path, *, branch: str) -> CaseMetric | None:
    case_id = str(entry.get("case_id") or "unknown-case")
    target = _clone_source(entry, workspace, branch=branch)
    if target is None:
        return None

    js_backend = str(entry.get("js_backend") or "").strip() or None
    payload = _scan_payload(target, workspace / f"{case_id}.json", js_backend=js_backend)
    rule_ids, cwes, findings, files_scanned = _collect_detected_sets(payload)
    signatures = _collect_detected_signatures(payload, target)

    expected_rules = {str(x).strip() for x in entry.get("expected_rule_ids", []) if str(x).strip()}
    expected_cwes = {str(x).strip().upper() for x in entry.get("expected_cwes", []) if str(x).strip()}
    forbidden_rules = {str(x).strip() for x in entry.get("forbidden_rule_ids", []) if str(x).strip()}
    forbidden_cwes = {str(x).strip().upper() for x in entry.get("forbidden_cwes", []) if str(x).strip()}
    expected_detailed = [x for x in entry.get("expected_findings_detailed", []) if isinstance(x, dict)]
    forbidden_detailed = [x for x in entry.get("forbidden_findings_detailed", []) if isinstance(x, dict)]

    expected_count = len(expected_rules) + len(expected_cwes)
    matched_expected = len(expected_rules & rule_ids) + len(expected_cwes & cwes)
    detailed_matched = 0
    detailed_missing = 0
    detailed_forbidden = 0

    if expected_detailed:
        detailed_matched, detailed_missing = _match_finding_specs(expected_detailed, signatures, target)
    if forbidden_detailed:
        detailed_forbidden, _ = _match_finding_specs(forbidden_detailed, signatures, target)

    false_negatives = max(expected_count - matched_expected, 0) + detailed_missing
    false_positives = len(forbidden_rules & rule_ids) + len(forbidden_cwes & cwes)
    false_positives += detailed_forbidden

    # When no explicit forbidden set is provided, approximate FP as non-expected findings.
    if (
        false_positives == 0
        and expected_count > 0
        and not forbidden_detailed
        and findings > matched_expected
    ):
        false_positives = findings - matched_expected

    true_positives = max(matched_expected, 0) + detailed_matched
    precision = _safe_float(float(true_positives), float(true_positives + false_positives))
    recall = _safe_float(float(true_positives), float(true_positives + false_negatives))
    f1 = _f1(precision, recall)

    return CaseMetric(
        case_id=case_id,
        findings=findings,
        files_scanned=files_scanned,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        f1_score=f1,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run multi-repo Ansede benchmark suite.")
    parser.add_argument("--repos", nargs="*", default=DEFAULT_REPOS, help="Git repository URLs to benchmark.")
    parser.add_argument("--branch", default="main", help="Branch to clone for each benchmark target.")
    parser.add_argument(
        "--manifest",
        default=DEFAULT_MANIFEST,
        help="Manifest JSON with benchmark entries and expected/forbidden CWE/rule IDs.",
    )
    parser.add_argument(
        "--no-manifest",
        action="store_true",
        help="Disable manifest-based evaluation and run URL-only aggregate mode.",
    )
    parser.add_argument(
        "--output",
        default="benchmarks/reports/latest.json",
        help="Path to write benchmark aggregate JSON.",
    )
    args = parser.parse_args()

    metrics: list[RepoMetric] = []
    case_metrics: list[CaseMetric] = []
    workspace = Path(tempfile.mkdtemp(prefix="ansede-bench-"))
    try:
        for repo_url in args.repos:
            name = repo_url.rsplit("/", 1)[-1].removesuffix(".git")
            dest = workspace / name
            clone = _run(["git", "clone", "--depth", "1", "--branch", args.branch, repo_url, str(dest)])
            if clone.returncode != 0:
                # Retry default branch if requested branch does not exist.
                clone = _run(["git", "clone", "--depth", "1", repo_url, str(dest)])
            if clone.returncode != 0:
                continue
            report = workspace / f"{name}.json"
            try:
                metrics.append(_scan_repo(dest, report))
            except RuntimeError:
                continue

        if not args.no_manifest:
            manifest_path = Path(args.manifest)
            if manifest_path.exists():
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    manifest = {}
                entries = manifest.get("entries", []) if isinstance(manifest, dict) else []
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    evaluated = _evaluate_manifest_case(entry, workspace, branch=args.branch)
                    if evaluated is not None:
                        case_metrics.append(evaluated)

        total_files = sum(item.files_scanned for item in metrics)
        total_findings = sum(item.findings for item in metrics)
        total_tp = sum(item.true_positives for item in case_metrics)
        total_fp = sum(item.false_positives for item in case_metrics)
        total_fn = sum(item.false_negatives for item in case_metrics)
        precision = _safe_float(float(total_tp), float(total_tp + total_fp))
        recall = _safe_float(float(total_tp), float(total_tp + total_fn))
        f1 = _f1(precision, recall)

        out_payload = {
            "benchmark_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "engine_version": "local",
            "aggregates": {
                "total_files_scanned": total_files,
                "total_findings": total_findings,
                "true_positives": total_tp,
                "false_positives": total_fp,
                "false_negatives": total_fn,
                "precision": round(precision, 4) if precision is not None else None,
                "recall": round(recall, 4) if recall is not None else None,
                "f1_score": round(f1, 4) if f1 is not None else None,
            },
            "repositories": {
                item.repo: {
                    "findings": item.findings,
                    "files_scanned": item.files_scanned,
                }
                for item in metrics
            },
            "cases": {
                item.case_id: {
                    "findings": item.findings,
                    "files_scanned": item.files_scanned,
                    "true_positives": item.true_positives,
                    "false_positives": item.false_positives,
                    "false_negatives": item.false_negatives,
                    "precision": round(item.precision, 4) if item.precision is not None else None,
                    "recall": round(item.recall, 4) if item.recall is not None else None,
                    "f1_score": round(item.f1_score, 4) if item.f1_score is not None else None,
                }
                for item in case_metrics
            },
        }

        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(out_payload, indent=2), encoding="utf-8")
        print(f"Benchmark report written to {out_path}")
        return 0
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
