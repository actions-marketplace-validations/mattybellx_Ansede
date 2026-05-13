from ansede_static.js_ast_analyzer import analyze_js_ast
import pathlib, tempfile

idx = pathlib.Path(tempfile.gettempdir()) / 'ansede-web-wild-cache' / 'OWASP__NodeGoat' / 'app' / 'routes' / 'index.js'
code = idx.read_text(errors='replace')
result = analyze_js_ast(code, str(idx))
for f in result.findings:
    print(f.rule_id, f.cwe, f.severity, f.confidence, f.title[:80])
