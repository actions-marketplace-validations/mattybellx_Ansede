"""Quick diagnostic for remaining benchmark FPs."""
import pathlib, tempfile, json, sys
sys.path.insert(0, 'src')
from ansede_static import scan_file

cache = pathlib.Path(tempfile.gettempdir()) / 'ansede-web-wild-cache'

files = [
    (cache / 'django__django' / 'django' / 'contrib' / 'admin' / 'static' / 'admin' / 'js' / 'vendor' / 'jquery' / 'jquery.min.js', 'jquery min'),
    (cache / 'django__django' / 'django' / 'contrib' / 'admin' / 'static' / 'admin' / 'js' / 'vendor' / 'select2' / 'select2.full.js', 'select2 full'),
    (cache / 'django__django' / 'django' / 'contrib' / 'auth' / 'admin.py', 'auth admin'),
    (cache / 'OWASP__NodeGoat' / 'app' / 'routes' / 'index.js', 'NodeGoat index'),
]

for fpath, label in files:
    if not fpath.exists():
        print(f'MISSING: {label} {fpath}')
        continue
    res = scan_file(fpath)
    for f in res.findings:
        d = f.as_dict()
        sev = d.get('severity', 'info')
        if isinstance(sev, str) and sev.lower() in ('high', 'critical'):
            print(f"{label}: {d.get('rule_id','?')} {d.get('cwe','?')} {sev} L{d.get('line',0)}: {d.get('title','')[:150]}")
