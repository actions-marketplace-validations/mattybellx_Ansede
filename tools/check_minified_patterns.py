import pathlib, tempfile, re

cache_dir = pathlib.Path(tempfile.gettempdir()) / 'ansede-web-wild-cache'

# Check xregexp for eval/new Function patterns
xr = cache_dir / 'django__django' / 'django' / 'contrib' / 'admin' / 'static' / 'admin' / 'js' / 'vendor' / 'xregexp' / 'xregexp.min.js'
code = xr.read_text(errors='replace')
print('xregexp size:', len(code))
has_eval = bool(re.search(r'(?<![\w.])eval\s*\(', code))
has_new_func = bool(re.search(r'new\s+Function\s*\(', code))
has_exec = bool(re.search(r'\bexec\s*\(', code))
print('xregexp: has_eval:', has_eval, 'has_new_func:', has_new_func, 'has_exec:', has_exec)
# Show new Function occurrences
for m in re.finditer(r'new\s+Function\s*\(', code):
    print('  new Function at', m.start(), ':', code[m.start()-20:m.start()+80])

# Check NodeGoat jquery for innerHTML
ng = cache_dir / 'OWASP__NodeGoat' / 'app' / 'assets' / 'vendor' / 'jquery.min.js'
code2 = ng.read_text(errors='replace')
for m in re.finditer(r'innerHTML\s*=', code2):
    ctx = code2[m.start()-30:m.start()+80]
    print('jquery innerHTML at', m.start(), ':', repr(ctx[:100]))
    break

# Check raphael for innerHTML
rp = cache_dir / 'OWASP__NodeGoat' / 'app' / 'assets' / 'vendor' / 'chart' / 'raphael-min.js'
code3 = rp.read_text(errors='replace')
for m in re.finditer(r'innerHTML\s*=', code3):
    ctx = code3[m.start()-30:m.start()+80]
    print('raphael innerHTML at', m.start(), ':', repr(ctx[:100]))
    break
