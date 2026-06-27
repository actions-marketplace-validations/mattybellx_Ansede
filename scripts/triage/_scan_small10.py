"""Scan 10 small repos quickly, one after another."""
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(r"C:\Users\matth\OneDrive\Desktop\ansede-static-focus")
TMP = ROOT / "tmp"
CLI = ["python", "-m", "ansede_static.cli"]

TARGETS = [
    # Python Flask/Django - small apps
    ("py1-microblog", "https://github.com/miguelgrinberg/microblog.git", "tmp/s_microblog", "Flask tutorial app"),
    ("py2-shorty", "https://github.com/coleifer/shorty.git", "tmp/s_shorty", "Flask URL shortener"),
    ("py3-flask-todo", "https://github.com/realpython/flask-jwt-extended-todo.git", "tmp/s_flasktodo", "Flask JWT todo app"),
    ("py4-django-blog", "https://github.com/gregblogs/django-blog.git", "tmp/s_djangoblog", "Django blog"),
    
    # JS/TS - small Node apps
    ("js5-express-todo", "https://github.com/bartstc/express-todo.git", "tmp/s_expresstodo", "Express todo app"),
    ("js6-node-api", "https://github.com/rahul1210x/rest-api-node.git", "tmp/s_nodeapi", "Node.js REST API"),
    ("js7-keystone", "https://github.com/keystonejs/keystone-classic.git", "tmp/s_keystone", "Node.js CMS"),
    
    # Go - small
    ("go8-gin-blog", "https://github.com/eddycjy/go-gin-blog.git", "tmp/s_ginblog", "Gin blog API"),
    
    # Python - small web tools
    ("py9-url-shortener", "https://github.com/bhrigu123/url-shortener.git", "tmp/s_urlshort", "Python URL shortener"),
    ("py10-pastebin", "https://github.com/mbrenner/pastebin.git", "tmp/s_pastebin", "Flask pastebin"),
]

results = {}

for idx, (name, repo, dest_rel, desc) in enumerate(TARGETS, 1):
    dest = ROOT / dest_rel
    
    # Clean any previous clone
    if dest.exists():
        shutil.rmtree(dest)
    
    print(f"\n{'='*60}")
    print(f"[{idx}/10] {name} — {desc}")
    print(f"  Repo: {repo}")
    
    # Clone
    start = time.time()
    r = subprocess.run(
        ["git", "clone", "--depth", "1", repo, str(dest)],
        capture_output=True, text=True, timeout=60
    )
    clone_time = time.time() - start
    print(f"  Clone: {clone_time:.0f}s")
    
    if not dest.exists():
        print(f"  FAILED to clone")
        results[name] = {"error": "clone failed"}
        continue
    
    # Scan
    out_file = TMP / f"tiny_{name}.json"
    start = time.time()
    r = subprocess.run(
        CLI + [str(dest), "--format", "json", "--output", str(out_file), "--fail-on", "never"],
        capture_output=True, text=True, timeout=120,
    )
    scan_time = time.time() - start
    
    # Parse
    if out_file.exists():
        try:
            data = json.loads(out_file.read_text(encoding="utf-8"))
            total = sum(len(rr.get("findings", [])) for rr in data.get("results", []))
            cwe_c = Counter()
            high_list = []
            for rr in data.get("results", []):
                for f in rr.get("findings", []):
                    cwe_c[f.get("cwe", "?")] += 1
                    sev = str(f.get("severity", "")).lower()
                    conf = f.get("confidence", 0)
                    if sev in ("critical", "high") and conf >= 0.7 and len(high_list) < 5:
                        high_list.append({
                            "cwe": f.get("cwe", "?"),
                            "sev": sev,
                            "conf": conf,
                            "file": str(rr.get("file_path", "")).split(chr(92))[-1].split("/")[-1],
                            "line": f.get("line", "?"),
                            "title": f.get("title", "")[:100],
                        })
            results[name] = {
                "total": total,
                "top_cwe": dict(cwe_c.most_common(3)),
                "high_crit": len(high_list),
                "top_high": high_list,
                "scan_time": f"{scan_time:.0f}s",
            }
            print(f"  Scan: {scan_time:.0f}s, {total} findings, top: {dict(cwe_c.most_common(3))}")
            
            # Clean up the clone to save space
            shutil.rmtree(dest)
            print(f"  Cleaned up")
            
        except Exception as e:
            print(f"  Parse error: {e}")
            results[name] = {"error": str(e)}
    else:
        print(f"  No output file")
        results[name] = {"error": "no output"}

# Summary
print(f"\n\n{'='*60}")
print(f"10 SMALL REPOS — COMPLETE")
print(f"{'='*60}")
print(f"{'#':<3} {'Name':<20} {'Findings':<10} {'Top CWE':<15} {'Top Finding':<50}")
print(f"{'-'*3} {'-'*20} {'-'*10} {'-'*15} {'-'*50}")
for idx, (name, r) in enumerate(list(results.items()), 1):
    if "error" in r:
        print(f"{idx:<3} {name:<20} {'ERR':<10} {r['error'][:60]}")
    else:
        top = r.get("top_high", [{}])[0]
        top_name = top.get("title", "none")[:48] if top else "none"
        top_cwe = list(r.get("top_cwe", {"?"}).keys())[0]
        print(f"{idx:<3} {name:<20} {r['total']:<10} {top_cwe:<15} {top_name:<50}")

print(f"\n{'='*60}")
print(f"HIGH+CRIT FINDINGS (sample)")
print(f"{'='*60}")
for name, r in results.items():
    if "error" not in r and r.get("top_high"):
        print(f"\n--- {name} ---")
        for h in r["top_high"][:2]:
            print(f"  [{h['sev'].upper()}] {h['cwe']} conf={h['conf']}  {h['file']}:{h['line']}")
            print(f"    {h['title']}")
