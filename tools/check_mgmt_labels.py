import sys, re, pathlib, tempfile
c = pathlib.Path(tempfile.gettempdir()) / 'ansede-web-wild-cache' / 'django__django'
for relpath in ['django/core/management/commands/compilemessages.py', 'django/conf/__init__.py']:
    f = c / relpath.replace('/', '\\')
    if not f.exists():
        print('MISSING:', relpath); continue
    code = f.read_text(errors='replace')
    lines = code.splitlines()
    UR = re.compile(r'sys\.argv|os\.environ|getenv', re.I)
    SK = re.compile(r'os\.path\.join|open\s*\(|Path\(', re.I)
    ul = [i for i, l in enumerate(lines) if UR.search(l)]
    sl = [i for i, l in enumerate(lines) if SK.search(l)]
    print(relpath.split('/')[-1], 'user:', ul[:5], 'sink:', sl[:5])
    for u in ul:
        for s in sl:
            if abs(u - s) <= 8:
                print('  HIT user_line=%d: %s' % (u+1, lines[u][:80]))
                print('      sink_line=%d: %s' % (s+1, lines[s][:80]))
