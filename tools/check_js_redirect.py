from ansede_static.js_engine.structure import collect_calls
from ansede_static.js_engine.taint import extract_taint_traces, DIRECT_TAINT_SOURCE_RE, trace_for_expr
import pathlib, tempfile, re

idx = pathlib.Path(tempfile.gettempdir()) / 'ansede-web-wild-cache' / 'OWASP__NodeGoat' / 'app' / 'routes' / 'index.js'
code = idx.read_text(errors='replace')
calls = collect_calls(code)
for c in calls:
    if 'redirect' in c.callee.lower():
        print('call:', repr(c.callee), '| args:', c.arguments[:2], '| line:', c.line)

traces = extract_taint_traces(code)
print('taint traces:', list(traces.keys())[:10])
test_expr = 'req.query.url'
m = DIRECT_TAINT_SOURCE_RE.search(test_expr)
print('direct match on req.query.url:', bool(m))
tf = trace_for_expr(test_expr, traces, line=1)
print('trace_for_expr result:', tf)
