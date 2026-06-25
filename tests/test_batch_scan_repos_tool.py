from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_module():
    script_path = Path(__file__).resolve().parents[1] / "tools" / "batch_scan_repos.py"
    spec = importlib.util.spec_from_file_location("batch_scan_repos", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_safe_repo_dir_name_is_stable_and_uniqueish():
    mod = _load_module()
    value = mod._safe_repo_dir_name("owner/repo")

    assert value.startswith("owner__repo-")
    assert len(value.split("-", 1)[1]) == 10


def test_normalize_languages_maps_typescript_and_validates():
    mod = _load_module()

    langs = mod._normalize_languages(["typescript", "python"])

    assert "javascript" in langs
    assert "python" in langs


def test_detect_language_from_suffix_handles_common_types():
    mod = _load_module()

    assert mod._detect_language_from_suffix(Path("a.py")) == "python"
    assert mod._detect_language_from_suffix(Path("b.ts")) == "javascript"
    assert mod._detect_language_from_suffix(Path("c.java")) == "java"
    assert mod._detect_language_from_suffix(Path("README.md")) is None


def test_load_repos_file_supports_campaign_entries_format(tmp_path: Path):
    mod = _load_module()
    source = {
        "entries": [
            {
                "repo": "octocat/hello-world",
                "url": "https://github.com/octocat/hello-world",
                "language": "python",
            }
        ]
    }
    path = tmp_path / "campaign.json"
    path.write_text(json.dumps(source), encoding="utf-8")

    repos = mod._load_repos_file(path)

    assert len(repos) == 1
    assert repos[0].full_name == "octocat/hello-world"
    assert repos[0].clone_url == "https://github.com/octocat/hello-world.git"


def test_run_batch_scan_reports_average_and_estimated_fp_rate(tmp_path: Path):
    mod = _load_module()

    repos = [
        mod.RepoSpec(full_name="a/b", clone_url="https://github.com/a/b.git"),
        mod.RepoSpec(full_name="c/d", clone_url="https://github.com/c/d.git"),
    ]

    mod._resolve_repo_checkout = lambda repo, cache_dir, refresh: tmp_path / repo.full_name.replace("/", "_")

    fake_cases = {
        "a/b": {
            "repo": "a/b",
            "files_scanned": 10,
            "lines_scanned": 100,
            "findings_count": 8,
            "top_cwes": [("CWE-862", 3)],
            "top_rules": [("PY-020", 3)],
            "audit_verdict_counts": {"TP": 3, "LIKELY_FP": 2, "NEEDS_REVIEW": 3},
            "estimated_fp_rate": 0.25,
        },
        "c/d": {
            "repo": "c/d",
            "files_scanned": 20,
            "lines_scanned": 300,
            "findings_count": 12,
            "top_cwes": [("CWE-601", 4)],
            "top_rules": [("JS-039", 4)],
            "audit_verdict_counts": {"TP": 7, "FP": 1, "NEEDS_REVIEW": 4},
            "estimated_fp_rate": 0.0833,
        },
    }
    mod._scan_repo = lambda repo, repo_dir, include_langs, max_files, js_backend, with_audit: fake_cases[repo.full_name]

    report = mod.run_batch_scan(
        repos,
        cache_dir=tmp_path,
        refresh=False,
        include_langs=set(),
        max_files_per_repo=10,
        js_backend="auto",
        with_audit=True,
    )

    summary = report["summary"]
    assert summary["repos_scanned"] == 2
    assert summary["findings_count"] == 20
    assert summary["average_findings_per_repo"] == 10.0
    assert summary["estimated_fp_rate"] == 0.15
