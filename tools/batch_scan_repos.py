from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ansede_static import (  # noqa: E402
    _CSHARP_EXTS,
    _GO_EXTS,
    _JAVA_EXTS,
    _JS_EXTS,
    _PHP_EXTS,
    _PYTHON_EXTS,
    _RUBY_EXTS,
    scan_file,
)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from benchmarks.external_corpus import _run_git  # noqa: E402
from ansede_static.engine.audit import audit_findings  # noqa: E402

SUPPORTED_LANGUAGES = ("python", "javascript", "typescript", "go", "java", "csharp", "ruby", "php")


@dataclass(frozen=True)
class RepoSpec:
    full_name: str
    clone_url: str
    default_branch: str = "main"
    stargazers_count: int = 0
    language: str = ""


def _default_cache_dir() -> Path:
    return Path(tempfile.gettempdir()) / "ansede-batch-repos"


def _safe_repo_dir_name(full_name: str) -> str:
    safe = full_name.replace("/", "__").replace("\\", "__").strip("._")
    digest = hashlib.sha256(full_name.encode("utf-8")).hexdigest()[:10]
    return f"{safe}-{digest}"


def _load_repos_file(path: Path) -> list[RepoSpec]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = _extract_repo_entries(data)
    repos: list[RepoSpec] = []
    for item in entries:
        spec = _repo_spec_from_entry(item)
        if spec is not None:
            repos.append(spec)
    return repos


def _extract_repo_entries(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("repos") or data.get("entries") or []
    return []


def _repo_spec_from_entry(item: Any) -> RepoSpec | None:
    if not isinstance(item, dict):
        return None
    full_name = str(item.get("full_name") or item.get("repo") or "").strip()
    clone_url = _extract_clone_url(item)
    if not full_name or not clone_url:
        return None
    return RepoSpec(
        full_name=full_name,
        clone_url=clone_url,
        default_branch=str(item.get("default_branch") or "main"),
        stargazers_count=int(item.get("stargazers_count") or 0),
        language=str(item.get("language") or ""),
    )


def _extract_clone_url(item: dict[str, Any]) -> str:
    clone_url = str(item.get("clone_url") or "").strip()
    if clone_url:
        return clone_url
    url = str(item.get("url") or "").strip()
    if url.startswith("https://github.com/"):
        return f"{url}.git" if not url.endswith(".git") else url
    return ""


def _api_json(url: str, token: str | None) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ansede-batch-scan/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req) as resp:
        payload = resp.read().decode("utf-8")
    return json.loads(payload)


def _fetch_repos_from_search(query: str, limit: int, token: str | None) -> list[RepoSpec]:
    repos: list[RepoSpec] = []
    page = 1
    per_page = min(100, max(1, limit))

    while len(repos) < limit:
        qs = urllib.parse.urlencode(
            {
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": per_page,
                "page": page,
            }
        )
        url = f"https://api.github.com/search/repositories?{qs}"
        data = _api_json(url, token)
        items = data.get("items", [])
        if not isinstance(items, list) or not items:
            break
        for item in items:
            if not isinstance(item, dict):
                continue
            full_name = str(item.get("full_name") or "").strip()
            clone_url = str(item.get("clone_url") or "").strip()
            if not full_name or not clone_url:
                continue
            repos.append(
                RepoSpec(
                    full_name=full_name,
                    clone_url=clone_url,
                    default_branch=str(item.get("default_branch") or "main"),
                    stargazers_count=int(item.get("stargazers_count") or 0),
                    language=str(item.get("language") or ""),
                )
            )
            if len(repos) >= limit:
                break
        page += 1

    return repos[:limit]


def _resolve_repo_checkout(repo: RepoSpec, cache_dir: Path, *, refresh: bool) -> Path:
    checkout_dir = cache_dir / _safe_repo_dir_name(repo.full_name)
    if refresh and checkout_dir.exists():
        shutil.rmtree(checkout_dir)

    if not checkout_dir.exists():
        cache_dir.mkdir(parents=True, exist_ok=True)
        _run_git(["clone", "--quiet", repo.clone_url, str(checkout_dir)])
    else:
        _run_git(["fetch", "--quiet", "origin"], cwd=checkout_dir)

    # Try main, then master, then any branch
    branch = repo.default_branch or "main"
    try:
        _run_git(["checkout", "--quiet", branch], cwd=checkout_dir)
    except RuntimeError:
        try:
            _run_git(["checkout", "--quiet", "master"], cwd=checkout_dir)
        except RuntimeError:
            # Checkout whatever HEAD is at
            _run_git(["checkout", "--quiet", "HEAD"], cwd=checkout_dir)
    try:
        _run_git(["pull", "--quiet", "--ff-only", "origin", branch], cwd=checkout_dir)
    except RuntimeError:
        _run_git(["pull", "--quiet", "--ff-only", "origin", "master"], cwd=checkout_dir)
    return checkout_dir


def _detect_language_from_suffix(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in _PYTHON_EXTS:
        return "python"
    if suffix in _JS_EXTS:
        # Includes TypeScript family under JS engine
        return "javascript"
    if suffix in _GO_EXTS:
        return "go"
    if suffix in _JAVA_EXTS:
        return "java"
    if suffix in _CSHARP_EXTS:
        return "csharp"
    if suffix in _RUBY_EXTS:
        return "ruby"
    if suffix in _PHP_EXTS:
        return "php"
    return None


def _iter_source_files(repo_dir: Path, include_langs: set[str], max_files: int) -> list[Path]:
    files: list[Path] = []
    for child in sorted(repo_dir.rglob("*")):
        if not child.is_file():
            continue
        if ".git" in child.parts:
            continue
        detected = _detect_language_from_suffix(child)
        if not detected:
            continue
        if include_langs and detected not in include_langs:
            continue
        files.append(child)
        if max_files > 0 and len(files) >= max_files:
            break
    return files


def _scan_repo(
    repo: RepoSpec,
    repo_dir: Path,
    include_langs: set[str],
    max_files: int,
    js_backend: str,
    *,
    with_audit: bool,
) -> dict[str, Any]:
    files = _iter_source_files(repo_dir, include_langs, max_files)
    analysis_results = []
    findings_count = 0
    lines_scanned = 0
    cwe_counter: Counter[str] = Counter()
    rule_counter: Counter[str] = Counter()

    for file_path in files:
        result = scan_file(file_path, js_backend=js_backend)
        analysis_results.append(result)
        lines_scanned += result.lines_scanned
        findings_count += len(result.findings)
        for finding in result.findings:
            if finding.cwe:
                cwe_counter[finding.cwe] += 1
            if finding.rule_id:
                rule_counter[finding.rule_id] += 1

    verdict_counts: dict[str, int] = {}
    estimated_fp_rate: float | None = None
    if with_audit and analysis_results:
        audit_report = audit_findings(analysis_results)
        verdict_counts = dict(audit_report.by_verdict)
        likely_fp = int(verdict_counts.get("FP", 0)) + int(verdict_counts.get("LIKELY_FP", 0))
        total = int(sum(verdict_counts.values()))
        estimated_fp_rate = (likely_fp / total) if total > 0 else None

    return {
        "repo": repo.full_name,
        "clone_url": repo.clone_url,
        "default_branch": repo.default_branch,
        "stars": repo.stargazers_count,
        "declared_language": repo.language,
        "files_scanned": len(files),
        "lines_scanned": lines_scanned,
        "findings_count": findings_count,
        "top_cwes": cwe_counter.most_common(10),
        "top_rules": rule_counter.most_common(10),
        "audit_verdict_counts": verdict_counts,
        "estimated_fp_rate": estimated_fp_rate,
    }


def run_batch_scan(
    repos: list[RepoSpec],
    *,
    cache_dir: Path,
    refresh: bool,
    include_langs: set[str],
    max_files_per_repo: int,
    js_backend: str,
    with_audit: bool,
) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    for repo in repos:
        repo_dir = _resolve_repo_checkout(repo, cache_dir, refresh=refresh)
        case = _scan_repo(
            repo,
            repo_dir,
            include_langs,
            max_files_per_repo,
            js_backend,
            with_audit=with_audit,
        )
        cases.append(case)

    total_files = sum(case["files_scanned"] for case in cases)
    total_lines = sum(case["lines_scanned"] for case in cases)
    total_findings = sum(case["findings_count"] for case in cases)
    average_findings_per_repo = (total_findings / len(cases)) if cases else 0.0

    aggregate_cwes: Counter[str] = Counter()
    aggregate_rules: Counter[str] = Counter()
    aggregate_verdicts: Counter[str] = Counter()
    for case in cases:
        aggregate_cwes.update(dict(case["top_cwes"]))
        aggregate_rules.update(dict(case["top_rules"]))
        aggregate_verdicts.update(case.get("audit_verdict_counts", {}))

    aggregate_estimated_fp_rate: float | None = None
    total_audited = int(sum(aggregate_verdicts.values()))
    if total_audited > 0:
        total_likely_fp = int(aggregate_verdicts.get("FP", 0)) + int(aggregate_verdicts.get("LIKELY_FP", 0))
        aggregate_estimated_fp_rate = total_likely_fp / total_audited

    return {
        "summary": {
            "repos_scanned": len(cases),
            "files_scanned": total_files,
            "lines_scanned": total_lines,
            "findings_count": total_findings,
            "average_findings_per_repo": average_findings_per_repo,
            "top_cwes": aggregate_cwes.most_common(15),
            "top_rules": aggregate_rules.most_common(15),
            "audit_verdict_counts": dict(aggregate_verdicts),
            "estimated_fp_rate": aggregate_estimated_fp_rate,
        },
        "repos": cases,
    }


def _normalize_languages(values: list[str]) -> set[str]:
    langs: set[str] = set()
    for value in values:
        text = str(value).strip().lower()
        if not text:
            continue
        if text in ("typescript", "ts"):
            langs.add("javascript")
            continue
        if text not in SUPPORTED_LANGUAGES:
            raise ValueError(f"unsupported language filter: {text}")
        langs.add(text)
    return langs


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch scan GitHub repositories with ansede-static and emit aggregate findings",
    )
    parser.add_argument(
        "--repos-file",
        type=Path,
        default=None,
        help="JSON file with repos list. Shape: {\"repos\": [{\"full_name\", \"clone_url\", ...}]}.",
    )
    parser.add_argument(
        "--github-query",
        default=None,
        help="GitHub search query used to discover repos (requires internet; token recommended).",
    )
    parser.add_argument("--limit", type=int, default=25, help="Maximum repositories to scan")
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=_default_cache_dir(),
        help="Cache directory for repository clones",
    )
    parser.add_argument("--refresh", action="store_true", help="Re-clone repositories instead of reusing cache")
    parser.add_argument(
        "--language",
        action="append",
        default=[],
        help="Language filter (repeatable): python/javascript/typescript/go/java/csharp/ruby/php",
    )
    parser.add_argument(
        "--max-files-per-repo",
        type=int,
        default=2000,
        help="Hard cap of files scanned per repository (0 = no cap)",
    )
    parser.add_argument(
        "--js-backend",
        choices=["auto", "regex", "structural"],
        default="auto",
        help="JavaScript analyzer backend",
    )
    parser.add_argument(
        "--with-audit",
        action="store_true",
        help="Run audit classification and include estimated false-positive rate",
    )
    parser.add_argument("--output", type=Path, default=None, help="Write full JSON report to a file")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress human-readable summary")
    args = parser.parse_args()

    if not args.repos_file and not args.github_query:
        parser.error("Provide at least one source: --repos-file or --github-query")

    include_langs = _normalize_languages(args.language)

    repos: list[RepoSpec] = []
    if args.repos_file:
        repos.extend(_load_repos_file(args.repos_file))

    if args.github_query:
        token = os.getenv("GITHUB_TOKEN")
        try:
            repos.extend(_fetch_repos_from_search(args.github_query, args.limit, token))
        except urllib.error.HTTPError as exc:
            parser.error(f"GitHub search request failed: HTTP {exc.code} {exc.reason}")
        except urllib.error.URLError as exc:
            parser.error(f"GitHub search request failed: {exc.reason}")

    # De-duplicate by full_name while preserving order
    seen: set[str] = set()
    unique_repos: list[RepoSpec] = []
    for repo in repos:
        key = repo.full_name.lower()
        if key in seen:
            continue
        seen.add(key)
        unique_repos.append(repo)

    selected = unique_repos[: max(1, args.limit)]
    report = run_batch_scan(
        selected,
        cache_dir=args.cache_dir,
        refresh=args.refresh,
        include_langs=include_langs,
        max_files_per_repo=max(0, args.max_files_per_repo),
        js_backend=args.js_backend,
        with_audit=args.with_audit,
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if not args.quiet:
        summary = report["summary"]
        print("\nansede-static batch scan")
        print("=" * 48)
        print(f"repos_scanned : {summary['repos_scanned']}")
        print(f"files_scanned : {summary['files_scanned']}")
        print(f"lines_scanned : {summary['lines_scanned']}")
        print(f"findings_count: {summary['findings_count']}")
        print(f"avg/repo     : {summary['average_findings_per_repo']:.2f}")
        if summary.get("estimated_fp_rate") is not None:
            print(f"est_fp_rate  : {summary['estimated_fp_rate']:.4f}")
        print("top_cwes      : " + ", ".join(f"{name} ({count})" for name, count in summary["top_cwes"][:8]))

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
