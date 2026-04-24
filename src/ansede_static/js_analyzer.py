"""
ansede_static.js_analyzer
──────────────────────────
Regex + token-level security analyzer for JavaScript / TypeScript source code.

Zero external dependencies — pure Python 3.11+ stdlib only.
Covers 18 vulnerability categories mapped to OWASP Top 10 / CWE.

Public API
──────────
    from ansede_static.js_analyzer import analyze_js
    findings = analyze_js(source_code, filename="app.js")
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger(__name__)

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame

# Inline suppression:  // ansede: ignore  |  // ansede: ignore[CWE-79]
_SUPPRESSION_RE: re.Pattern[str] = re.compile(
    r'(?://|/\*)\s*ansede:\s*ignore(?:\[([\w\-,\s]+)\])?', re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────────────────────
# Rule helpers
# ──────────────────────────────────────────────────────────────────────────────

def _match_lines(pattern: str | re.Pattern, code: str, flags: int = re.IGNORECASE) -> list[int]:
    """Return 1-based line numbers that match the given pattern."""
    if isinstance(pattern, str):
        compiled = re.compile(pattern, flags)
    else:
        compiled = pattern
    result: list[int] = []
    for i, line in enumerate(code.splitlines(), 1):
        s = line.strip()
        if s.startswith("//") or s.startswith("*"):
            continue
        if compiled.search(line):
            result.append(i)
    return result


_COMMENT_LINE_RE = re.compile(r"^\s*(?://|/\*|\*)")


def _strip_comments(line: str) -> str:
    out = re.sub(r"//.*$", "", line)
    out = re.sub(r"/\*.*?\*/", "", out)
    return out


@dataclass(frozen=True)
class _RouteBlock:
    method: str
    path: str
    start_line: int
    end_line: int
    code: str


# ──────────────────────────────────────────────────────────────────────────────
# Rule definitions
# ──────────────────────────────────────────────────────────────────────────────

class _Rule:
    def __init__(
        self,
        rule_id: str,
        cwe: str,
        title_tmpl: str,
        desc_tmpl: str,
        suggestion: str,
        severity: Severity,
        pattern: str | re.Pattern,
        flags: int = re.IGNORECASE,
        exclude_pattern: str | None = None,
        context_confirm: str | None = None,
        context_lines: int = 3,
        negate_context: bool = False,
    ):
        self.rule_id = rule_id
        self.cwe = cwe
        self.title_tmpl = title_tmpl
        self.desc_tmpl = desc_tmpl
        self.suggestion = suggestion
        self.severity = severity
        self.pattern = re.compile(pattern, flags) if isinstance(pattern, str) else pattern
        self.exclude_re = re.compile(exclude_pattern, re.IGNORECASE) if exclude_pattern else None
        self.context_confirm = re.compile(context_confirm, re.IGNORECASE) if context_confirm else None
        self.context_lines = context_lines
        self.negate_context = negate_context

    def check(self, code: str, filename: str = "") -> list[Finding]:
        lines = code.splitlines()
        findings: list[Finding] = []
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if _COMMENT_LINE_RE.match(stripped):
                continue
            if not self.pattern.search(line):
                continue
            if self.exclude_re and self.exclude_re.search(line):
                continue
            if self.context_confirm:
                ctx_start = max(0, lineno - 1 - self.context_lines)
                ctx_end = min(len(lines), lineno - 1 + self.context_lines + 1)
                ctx = "\n".join(lines[ctx_start:ctx_end])
                found = bool(self.context_confirm.search(ctx))
                # negate_context: flag when pattern is ABSENT (e.g. missing auth)
                if self.negate_context:
                    if found:
                        continue
                else:
                    if not found:
                        continue
            findings.append(Finding(
                category="security",
                severity=self.severity,
                title=self.title_tmpl.format(line=lineno),
                description=self.desc_tmpl.format(
                    line=lineno,
                    snippet=stripped[:90],
                ),
                line=lineno,
                suggestion=self.suggestion,
                rule_id=self.rule_id,
                cwe=self.cwe,
                agent="js-analyzer",
            ))
        return findings


# ──────────────────────────────────────────────────────────────────────────────
# Rule catalogue
# ──────────────────────────────────────────────────────────────────────────────

_RULES: list[_Rule] = [

    # ── CWE-79: XSS via innerHTML / outerHTML / document.write ────────────
    _Rule(
        "JS-001", "CWE-79",
        "CWE-79: XSS via innerHTML assignment at line {line}",
        "Unsanitized data assigned to `innerHTML` or `outerHTML` at L{line}: `{snippet}`. "
        "An attacker can inject a `<script>` tag or event handler that executes in the victim's browser.",
        "Use `textContent` instead of `innerHTML`, or sanitize with DOMPurify.sanitize(). "
        "Never concatenate user data into HTML.",
        Severity.CRITICAL,
        r'\.innerHTML\s*=|\.outerHTML\s*=',
        # Only exclude when the entire RHS is a static string with no concatenation or interpolation
        exclude_pattern=r'DOMPurify\.sanitize|textContent|\.innerHTML\s*=\s*["\'][^"\']*["\']\s*[;,)]?\s*$',
    ),

    _Rule(
        "JS-002", "CWE-79",
        "CWE-79: XSS via document.write() at line {line}",
        "`document.write()` called with dynamic content at L{line}: `{snippet}`. "
        "Any user-controlled string passed here runs as raw HTML.",
        "Replace with safe DOM methods: `document.createElement()` + `textContent`.",
        Severity.CRITICAL,
        r'document\.write(?:ln)?\s*\(',
    ),

    _Rule(
        "JS-003", "CWE-79",
        "CWE-79: XSS via dangerouslySetInnerHTML at line {line}",
        "React `dangerouslySetInnerHTML` used at L{line}: `{snippet}`. "
        "Passing unsanitized data here bypasses React's XSS protection entirely.",
        "Sanitize with DOMPurify.sanitize() before setting dangerouslySetInnerHTML. "
        "Prefer rendering plain text if HTML is not needed.",
        Severity.HIGH,
        r'dangerouslySetInnerHTML',
    ),

    # ── CWE-95: Code injection ─────────────────────────────────────────────
    _Rule(
        "JS-004", "CWE-95",
        "CWE-95: Code injection via eval() at line {line}",
        "`eval()` called at L{line}: `{snippet}`. "
        "If the argument includes any user-controlled data, an attacker can execute arbitrary JavaScript.",
        "Eliminate eval(). Use JSON.parse() for data, or a safe expression library.",
        Severity.CRITICAL,
        r'\beval\s*\(',
        exclude_pattern=r'//|eval\s*\(\s*["\']',
    ),

    _Rule(
        "JS-005", "CWE-95",
        "CWE-95: Code injection via new Function() at line {line}",
        "`new Function(...)` at L{line}: `{snippet}`. "
        "This is equivalent to eval(); any user-controlled string becomes executable code.",
        "Avoid new Function(). If dynamic logic is required, use a safe interpreter.",
        Severity.CRITICAL,
        r'\bnew\s+Function\s*\(',
    ),

    _Rule(
        "JS-006", "CWE-95",
        "CWE-95: setTimeout/setInterval with string argument at line {line}",
        "`setTimeout` or `setInterval` called with a string at L{line}: `{snippet}`. "
        "String arguments are evaluated like eval(); dynamic content enables code injection.",
        "Always pass a function reference: `setTimeout(() => handler(), delay)` — never a string.",
        Severity.HIGH,
        r'set(?:Timeout|Interval)\s*\(\s*[^,)]*\+',
    ),

    # ── CWE-78: Command injection ─────────────────────────────────────────
    _Rule(
        "JS-007", "CWE-78",
        "CWE-78: Command injection via exec() at line {line}",
        "`child_process.exec()` called with a dynamic/concatenated command at L{line}: `{snippet}`. "
        "Shell metacharacters in user input can execute arbitrary OS commands.",
        "Use `execFile()` or `spawn()` with an argument array (never shell=true + user input). "
        "Validate with a strict allowlist if exec is required.",
        Severity.CRITICAL,
        r'(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*["\' ]\s*\+)',
    ),

    _Rule(
        "JS-008", "CWE-78",
        "CWE-78: Command injection via spawn with shell:true at line {line}",
        "`spawn()` or `execFile()` called with `shell: true` at L{line}: `{snippet}`. "
        "This instructs Node.js to invoke the shell, enabling metacharacter injection.",
        "Remove `shell: true`. Pass a list: `spawn('cmd', [arg1, arg2])`.",
        Severity.CRITICAL,
        r'(?:spawn|execFile)\s*\([^)]*shell\s*:\s*true',
    ),

    # ── CWE-89: SQL injection ─────────────────────────────────────────────
    _Rule(
        "JS-009", "CWE-89",
        "CWE-89: SQL injection via string concatenation at line {line}",
        "SQL query assembled with string concatenation at L{line}: `{snippet}`. "
        "An attacker can break out of the query context and read, modify, or delete data.",
        "Use parameterized queries: `db.query('SELECT ... WHERE id = $1', [id])`.",
        Severity.CRITICAL,
        r'(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*["\' ]\s*\+)',
    ),

    _Rule(
        "JS-010", "CWE-89",
        "CWE-89: SQL injection via template literal query at line {line}",
        "SQL query uses a template literal with interpolation at L{line}: `{snippet}`. "
        "Template literals in SQL calls are equivalent to string concatenation.",
        "Replace template literal with a parameterized placeholder: `WHERE id = $1`.",
        Severity.CRITICAL,
        r'(?:query|execute|sequelize\.query|knex\.raw)\s*\(`[^`]*\$\{',
    ),

    # ── CWE-798: Hardcoded secrets ─────────────────────────────────────────
    _Rule(
        "JS-011", "CWE-798",
        "CWE-798: Hardcoded credential at line {line}",
        "A credential, key, or password appears to be hardcoded at L{line}: `{snippet}`. "
        "Commit history will permanently expose this credential even after removal.",
        "Move secrets to environment variables: `process.env.API_KEY`. "
        "Use a secrets manager for production.",
        Severity.CRITICAL,
        r'(?:api[_-]?key|apikey|secret|password|token|auth_token|private[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{8,}["\']',
        exclude_pattern=r'process\.env|TEST|FAKE|PLACEHOLDER|your[-_]|<YOUR',
    ),

    _Rule(
        "JS-012", "CWE-798",
        "CWE-798: AWS credential hardcoded at line {line}",
        "AWS access key or secret key hardcoded at L{line}: `{snippet}`. "
        "This grants full AWS account access to anyone with the source.",
        "Use IAM roles with instance profiles or AWS Secrets Manager. Never hardcode AWS credentials.",
        Severity.CRITICAL,
        r'(?:AKIA|ASIA)[A-Z0-9]{16}|aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\'][^"\']{20,}["\']',
    ),

    # ── CWE-22: Path traversal ─────────────────────────────────────────────
    _Rule(
        "JS-013", "CWE-22",
        "CWE-22: Path traversal via user-controlled file path at line {line}",
        "A file-system operation uses a path from `req.params`, `req.query`, or `req.body` at L{line}: "
        "`{snippet}`. An attacker can use `../` sequences to read or write arbitrary files.",
        "Sanitize: `const safe = path.basename(userPath)` then verify "
        "`path.resolve(BASE, safe).startsWith(path.resolve(BASE))`.",
        Severity.HIGH,
        r'(?:fs\.|path\.)(?:read|write|createRead|createWrite|open|unlink|stat|access)\w*\s*\([^)]*req\.\w+',
    ),

    # ── CWE-601: Open redirect ─────────────────────────────────────────────
    _Rule(
        "JS-014", "CWE-601",
        "CWE-601: Open redirect via user-controlled URL at line {line}",
        "`res.redirect()` uses value from `req.query`, `req.body`, or `req.params` at L{line}: "
        "`{snippet}`. An attacker can redirect users to a phishing site.",
        "Validate redirect target against an allowlist of permitted URLs or paths.",
        Severity.HIGH,
        r'res\.redirect\s*\([^)]*req\.\w+',
    ),

    # ── CWE-918: SSRF ────────────────────────────────────────────────────────
    _Rule(
        "JS-015", "CWE-918",
        "CWE-918: SSRF — user-controlled URL in HTTP client call at line {line}",
        "`fetch()`, `axios`, or `request()` called with a URL from `req.*` at L{line}: `{snippet}`. "
        "An attacker can target internal services (cloud metadata 169.254.169.254, Redis, etc.).",
        "Validate URL: parse with `new URL(target)`, check hostname in ALLOWED_HOSTS, "
        "block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x).",
        Severity.HIGH,
        r'(?:fetch|axios\.(?:get|post)|request|got|needle)\s*\([^)]*req\.\w+',
    ),

    # ── CWE-338: Weak PRNG ────────────────────────────────────────────────────
    _Rule(
        "JS-016", "CWE-338",
        "CWE-338: Weak PRNG (Math.random) in security context at line {line}",
        "`Math.random()` used near security-sensitive code at L{line}: `{snippet}`. "
        "Math.random is NOT cryptographically secure. Attackers who observe some outputs may predict future ones.",
        "Use `crypto.randomBytes(32)` (Node.js) or `crypto.getRandomValues()` (browser).",
        Severity.MEDIUM,
        r'Math\.random\s*\(',
        context_confirm=r'token|secret|key|password|nonce|session|auth|csrf|salt|otp|invite|reset',
        context_lines=4,
    ),

    # ── CWE-312: Sensitive data in localStorage ────────────────────────────
    _Rule(
        "JS-017", "CWE-312",
        "CWE-312: Sensitive data stored in localStorage at line {line}",
        "`localStorage.setItem()` stores data that appears to be a credential or PII at L{line}: "
        "`{snippet}`. localStorage is accessible to any JavaScript on the origin (XSS risk) "
        "and persists indefinitely.",
        "Store session tokens in httpOnly cookies (inaccessible to JS). "
        "Never store passwords or unencrypted JWTs in localStorage.",
        Severity.MEDIUM,
        r'localStorage\.setItem\s*\([^)]*(?:password|token|secret|ssn|credit.?card|private)',
    ),

    # ── CWE-1321: Prototype pollution ─────────────────────────────────────
    _Rule(
        "JS-018", "CWE-1321",
        "CWE-1321: Prototype pollution risk at line {line}",
        "Object modification using `__proto__`, `constructor.prototype`, or `Object.assign` with "
        "unchecked user input at L{line}: `{snippet}`. Polluting Object.prototype affects all objects.",
        "Validate keys: `if (key === '__proto__' || key === 'constructor') throw ...`. "
        "Use `Object.create(null)` for key-value stores. Prefer `structuredClone()` over merge.",
        Severity.HIGH,
        r'__proto__|constructor\.prototype|Object\.assign\s*\([^)]*req\.\w+',
    ),

    # ── CWE-1004: Missing httpOnly flag on cookies ─────────────────────────
    _Rule(
        "JS-019", "CWE-1004",
        "CWE-1004: Cookie set without httpOnly flag at line {line}",
        "`res.cookie()` called without `httpOnly: true` at L{line}: `{snippet}`. "
        "Cookies without httpOnly are accessible to JavaScript, making them stealable via XSS.",
        "Always set `httpOnly: true` and `secure: true`: "
        "`res.cookie('session', value, { httpOnly: true, secure: true, sameSite: 'strict' })`.",
        Severity.MEDIUM,
        r'res\.cookie\s*\(',
        exclude_pattern=r'httpOnly\s*:\s*true',
    ),

    # ── CWE-345: JWT with disabled verification ────────────────────────────
    _Rule(
        "JS-020", "CWE-345",
        "CWE-345: JWT signature verification disabled at line {line}",
        "JWT decode/verify call has verification disabled at L{line}: `{snippet}`. "
        "An attacker can forge arbitrary tokens and impersonate any user.",
        "Never disable signature verification. Remove `verify: false` and `algorithms: []`.",
        Severity.CRITICAL,
        r'(?:verify|decode)\s*\([^)]*(?:verify\s*:\s*false|algorithms\s*:\s*\[\s*\])',
    ),

    # ── CWE-942: CORS wildcard ────────────────────────────────────────────
    _Rule(
        "JS-021", "CWE-942",
        "CWE-942: CORS wildcard origin at line {line}",
        "CORS is configured to allow all origins (`*`) at L{line}: `{snippet}`. "
        "In conjunction with credentials, this allows any website to make authenticated requests.",
        "Set `origin` to a specific allowlist of trusted domains instead of `'*'`.",
        Severity.MEDIUM,
        r'origin\s*:\s*["\'][*]["\']|allowedOrigins\s*:\s*\[\s*["\'][*]["\']',
    ),

    # ── CWE-209: Error details in HTTP response ────────────────────────────
    _Rule(
        "JS-022", "CWE-209",
        "CWE-209: Error details leaked in HTTP response at line {line}",
        "Internal error messages or stack traces sent to the client at L{line}: `{snippet}`. "
        "Stack traces reveal file paths, library versions, and logic that aid attackers.",
        "Return generic error messages to clients. Log full errors server-side. "
        "`res.status(500).json({ error: 'Internal server error' })`.",
        Severity.MEDIUM,
        # Match direct calls and chained: res.status(500).json(...err.message...)
        r'res(?:\.status\s*\([^)]*\))?[.\s]*(?:send|json)\s*\([^)]*(?:err\.message|err\.stack|error\.stack|e\.message)',
    ),

    # ── CWE-98: Dynamic require ────────────────────────────────────────────
    _Rule(
        "JS-023", "CWE-98",
        "CWE-98: Dynamic require() with variable path at line {line}",
        "`require()` called with a non-literal argument at L{line}: `{snippet}`. "
        "If the path comes from user-controlled data, an attacker can load arbitrary modules.",
        "Use static `require('module-name')` only. Never pass user input to require().",
        Severity.HIGH,
        r'\brequire\s*\(\s*(?!["\'`](?:\.\/|\.\.\/|[a-z])[^"\'`]*["\'`]\s*\))[^"\'`\s]',
    ),

    # ── CWE-1333: ReDoS ───────────────────────────────────────────────────
    _Rule(
        "JS-024", "CWE-1333",
        "CWE-1333: Potential ReDoS — catastrophic backtracking regex at line {line}",
        "Regex with nested quantifiers or ambiguous alternation at L{line}: `{snippet}`. "
        "Crafted input can cause exponential backtracking, locking the event loop.",
        "Use non-backtracking patterns. Test with ReDoS tools (safe-regex, vuln-regex-detector). "
        "Set a timeout on regex execution or use the `re2` library.",
        Severity.MEDIUM,
        r'new RegExp\(|/(?:[^/\\]|\\.)*(?:\+|\*|\{[\d,]+\})(?:[^/\\]|\\.)*(?:\+|\*|\{[\d,]+\})',
    ),

    # ── CWE-312: JWT stored in localStorage (specific pattern) ────────────
    _Rule(
        "JS-026", "CWE-312",
        "CWE-312: JWT stored in localStorage at line {line}",
        "`localStorage.setItem` called with a JWT value at L{line}: `{snippet}`. "
        "localStorage is accessible to JavaScript — a single XSS flaw steals all sessions.",
        "Store authentication tokens in httpOnly, secure, SameSite=Strict cookies.",
        Severity.HIGH,
        r'localStorage\.setItem\s*\([^)]*jwt|localStorage\.setItem\s*\([^)]*[Tt]oken',
    ),

    # ── CWE-116: Missing output encoding — template literals in HTML context ─
    _Rule(
        "JS-027", "CWE-79",
        "CWE-79: XSS via unencoded template literal inserted into HTML at line {line}",
        "Template literal with user data appended to `.innerHTML` or DOM at L{line}: `{snippet}`.",
        "Encode output: use `encodeURIComponent()` for URLs, `DOMPurify.sanitize()` for HTML.",
        Severity.HIGH,
        r'innerHTML\s*\+=\s*`[^`]*\$\{|innerHTML\s*=\s*`[^`]*\$\{',
    ),

    # ── Missing CSRF protection detection ─────────────────────────────────
    _Rule(
        "JS-028", "CWE-352",
        "CWE-352: State-mutating route may lack CSRF protection at line {line}",
        "POST/PUT/PATCH/DELETE route defined at L{line} (`{snippet}`). "
        "Without CSRF tokens or SameSite cookies, authenticated users can be tricked into "
        "submitting unwanted requests.",
        "Use a CSRF middleware (`csurf`, `csrf-csrf`) or set `SameSite=Strict` on session cookies.",
        Severity.MEDIUM,
        r'(?:app|router)\.(?:post|put|patch|delete)\s*\(["\']',
        context_confirm=r'csrf|xsrf|SameSite|csurf',
        context_lines=20,
        negate_context=True,
    ),
]


# ──────────────────────────────────────────────────────────────────────────────
# Context-aware rules that need multi-line awareness
# ──────────────────────────────────────────────────────────────────────────────

def _check_no_rate_limit(code: str) -> list[Finding]:
    """Detect auth routes with no rate-limiting middleware."""
    findings: list[Finding] = []
    lines = code.splitlines()
    auth_route_re = re.compile(
        r'(?:app|router)\.post\s*\(["\'](?:[^"\']*(?:login|signin|sign-in|authenticate|auth)'
        r'[^"\']*)["\']',
        re.IGNORECASE,
    )
    rate_limit_re = re.compile(r'rateLimit|rate.?limiter|throttle|slowDown', re.IGNORECASE)

    # Check entire file for any rate-limiting import/use
    has_rate_limit = bool(rate_limit_re.search(code))

    for lineno, line in enumerate(lines, 1):
        if _COMMENT_LINE_RE.match(line.strip()):
            continue
        if auth_route_re.search(line) and not has_rate_limit:
            findings.append(Finding(
                category="security",
                severity=Severity.MEDIUM,
                title=f"CWE-307: No rate limiting on auth route at line {lineno}",
                description=(
                    f"Authentication route at L{lineno} (`{line.strip()[:80]}`) has no rate-limiting "
                    f"middleware in scope. An attacker can brute-force credentials."
                ),
                line=lineno,
                suggestion=(
                    "Apply rate limiting: `const limiter = rateLimit({ windowMs: 15*60*1000, max: 10 })`. "
                    "Apply before the auth handler."
                ),
                rule_id="JS-029",
                cwe="CWE-307",
                agent="js-analyzer",
            ))
    return findings


def _check_hardcoded_jwt_secret(code: str) -> list[Finding]:
    """Detect JWT signed with a hardcoded secret."""
    findings: list[Finding] = []
    pattern = re.compile(
        r'jwt\.sign\s*\([^,]+,\s*["\'][^"\']{4,}["\']',
        re.IGNORECASE,
    )
    env_pattern = re.compile(r'process\.env', re.IGNORECASE)
    for lineno, line in enumerate(code.splitlines(), 1):
        if _COMMENT_LINE_RE.match(line.strip()):
            continue
        if pattern.search(line) and not env_pattern.search(line):
            findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL,
                title=f"CWE-798: JWT signed with hardcoded secret at line {lineno}",
                description=(
                    f"`jwt.sign()` uses a hardcoded string as the secret at L{lineno}: "
                    f"`{line.strip()[:80]}`. Anyone with the source can forge tokens."
                ),
                line=lineno,
                suggestion="Move the secret to `process.env.JWT_SECRET` and load it at startup.",
                rule_id="JS-030",
                cwe="CWE-798",
                agent="js-analyzer",
            ))
    return findings


def _check_sensitive_console_log(code: str) -> list[Finding]:
    """Detect console.log of passwords, tokens, or private keys."""
    findings: list[Finding] = []
    pattern = re.compile(
        r'console\.(?:log|debug|info|warn|error)\s*\([^)]*(?:password|passwd|token|secret|private|'
        r'apikey|api_key|credit.?card|ssn)',
        re.IGNORECASE,
    )
    for lineno, line in enumerate(code.splitlines(), 1):
        if _COMMENT_LINE_RE.match(line.strip()):
            continue
        if pattern.search(line):
            findings.append(Finding(
                category="security",
                severity=Severity.MEDIUM,
                title=f"CWE-312: Sensitive data logged to console at line {lineno}",
                description=(
                    f"Sensitive data logged with `console.log/debug/error` at L{lineno}: "
                    f"`{line.strip()[:80]}`. Logs may be captured by monitoring tools or accessible "
                    f"to third parties."
                ),
                line=lineno,
                suggestion="Remove or redact sensitive values before logging. Use structured logging with field filtering.",
                rule_id="JS-031",
                cwe="CWE-312",
                agent="js-analyzer",
            ))
    return findings


def _check_dangerous_object_merge(code: str) -> list[Finding]:
    """Detect Object.assign or spread into options/config with req.body — prototype pollution."""
    findings: list[Finding] = []
    pattern = re.compile(
        r'Object\.assign\s*\([^)]*req\.body|{\s*\.\.\.\s*req\.body',
        re.IGNORECASE,
    )
    for lineno, line in enumerate(code.splitlines(), 1):
        if _COMMENT_LINE_RE.match(line.strip()):
            continue
        if pattern.search(line):
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-1321: Prototype pollution via Object.assign/spread at line {lineno}",
                description=(
                    f"Spreading `req.body` directly into an object at L{lineno}: `{line.strip()[:80]}`. "
                    f"A malicious `__proto__` key in the body contaminates all objects."
                ),
                line=lineno,
                suggestion="Sanitize keys first: use a schema validator (Joi, Zod) or strip `__proto__`/`constructor` keys.",
                rule_id="JS-032",
                cwe="CWE-1321",
                agent="js-analyzer",
            ))
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Taint-variable indirect tracking
# ──────────────────────────────────────────────────────────────────────────────

_TAINT_VAR_RE = re.compile(
    r'(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?req\.',
    re.IGNORECASE,
)

_ASSIGNMENT_RE = re.compile(
    r'(?:(?:const|let|var)\s+)?([A-Za-z_$]\w*)\s*=\s*(.+?);?\s*$',
)

_REQ_SOURCE_RE = re.compile(
    r'\breq\.(?:params|query|body|headers|cookies)\b',
    re.IGNORECASE,
)


def _expr_references_taint(expr: str, taint_vars: set[str]) -> bool:
    """Return True if an expression references any currently tainted variable."""
    return any(re.search(rf'\b{re.escape(var)}\b', expr) for var in taint_vars)


def _append_trace(
    trace: tuple[TraceFrame, ...],
    kind: str,
    label: str,
    *,
    line: int | None = None,
) -> tuple[TraceFrame, ...]:
    """Append a trace frame if it does not duplicate the most recent step."""
    frame = TraceFrame(kind=kind, label=label, line=line)
    if trace and trace[-1] == frame:
        return trace
    return trace + (frame,)


def _merge_traces(*traces: tuple[TraceFrame, ...]) -> tuple[TraceFrame, ...]:
    """Merge multiple trace sequences while avoiding duplicate adjacent frames."""
    merged: tuple[TraceFrame, ...] = ()
    for trace in traces:
        for frame in trace:
            if merged and merged[-1] == frame:
                continue
            merged += (frame,)
    return merged


def _extract_taint_traces(code: str, *, line_offset: int = 0) -> dict[str, tuple[TraceFrame, ...]]:
    """Return tainted variables with source/alias/helper traces derived from req.* input."""
    taint_traces: dict[str, tuple[TraceFrame, ...]] = {}
    lines = code.splitlines()

    for _ in range(4):
        changed = False
        for lineno, line in enumerate(lines, 1 + line_offset):
            stripped = _strip_comments(line).strip()
            if not stripped or _COMMENT_LINE_RE.match(stripped):
                continue
            match = _ASSIGNMENT_RE.match(stripped)
            if not match:
                continue
            target, expr = match.groups()
            if target in taint_traces:
                continue
            if _REQ_SOURCE_RE.search(expr):
                taint_traces[target] = (
                    TraceFrame(kind="source", label=f"source `{expr[:80]}`", line=lineno),
                    TraceFrame(kind="propagator", label=f"assign to `{target}`", line=lineno),
                )
                changed = True
                continue

            referenced = [var for var in taint_traces if re.search(rf'\b{re.escape(var)}\b', expr)]
            if referenced:
                trace = taint_traces[referenced[0]]
                if re.search(r'\b\w+\s*\(', expr):
                    trace = _append_trace(trace, "helper", f"through `{expr[:80]}`", line=lineno)
                else:
                    trace = _append_trace(trace, "propagator", f"via `{expr[:80]}`", line=lineno)
                trace = _append_trace(trace, "propagator", f"assign to `{target}`", line=lineno)
                taint_traces[target] = trace
                changed = True
        if not changed:
            break

    return taint_traces


_ROUTE_START_RE = re.compile(
    r'(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*([\'"])(.+?)\2',
    re.IGNORECASE,
)
_ROUTE_PARAM_RE = re.compile(r':([A-Za-z_$][\w$]*)')
_RESOURCE_PARAM_RE = re.compile(r'(?:^|_)(?:id|uid|pk|slug)$|(?:Id|Uid|Pk|Slug)$', re.IGNORECASE)
_AUTH_MIDDLEWARE_RE = re.compile(
    r'requireAuth|authMiddleware|isAuthenticated|isLoggedIn|passport\.authenticate|'
    r'verifyToken|checkAuth|ensureAuth|jwtAuth|requireLogin|'
    r'requireAdmin|adminOnly|adminRequired|ensureAdmin|staffOnly|staffRequired|'
    r'requireRole|hasRole|checkRole|requirePermission|checkPermission|hasPermission',
    re.IGNORECASE,
)
_PRIVILEGE_MIDDLEWARE_RE = re.compile(
    r'requireAdmin|adminOnly|adminRequired|ensureAdmin|staffOnly|staffRequired|'
    r'superuserOnly|rootOnly|requireRole|hasRole|checkRole|requirePermission|'
    r'checkPermission|hasPermission|authorizeRole|permissionMiddleware',
    re.IGNORECASE,
)
_OWNERSHIP_KEY_RE = re.compile(
    r'ownerId|userId|accountId|tenantId|authorId|createdBy|organizationId|orgId',
    re.IGNORECASE,
)
_PRINCIPAL_REF_RE = re.compile(
    r'req\.(?:user|auth)|res\.locals\.user|currentUser|session\.user|'
    r'req\.session\.(?:user|auth)|req\.session\[\s*["\']user(?:Id)?["\']\s*\]',
    re.IGNORECASE,
)
_LOOKUP_SINK_RE = re.compile(
    r'findByPk\s*\(|findById\s*\(|findOne\s*\(|findUnique\s*\(|findFirst\s*\(|'
    r'select\s+.+\bwhere\b',
    re.IGNORECASE,
)
_DIRECT_MUTATION_SINK_RE = re.compile(
    r'destroy\s*\(|update\s*\(|deleteOne\s*\(|remove\s*\(|'
    r'findByIdAndUpdate\s*\(|findByIdAndDelete\s*\(|findOneAndUpdate\s*\(|'
    r'findOneAndDelete\s*\(|\bUPDATE\s+\w+\s+SET\b|\bDELETE\s+FROM\b',
    re.IGNORECASE,
)
_INSTANCE_MUTATION_RE = re.compile(r'\b([A-Za-z_$][\w$]*)\s*\.\s*(destroy|save|remove|update)\s*\(', re.IGNORECASE)
_PUBLIC_ROUTE_RE = re.compile(
    r'/(?:login|signin|sign-in|signup|sign-up|register|authenticate|forgot|reset|callback|'
    r'logout|health|ping|status|healthz|ready|readiness|liveness|docs|swagger|openapi|'
    r'public|home|about|terms|privacy|favicon|robots|version)(?:/|$)',
    re.IGNORECASE,
)
_ADMIN_ROUTE_RE = re.compile(r'/(?:admin|internal|staff|superuser|root)(?:/|$)', re.IGNORECASE)
_PRIVILEGE_KEY_RE = re.compile(r'admin|staff|superuser|root|role|permission|scope|acl|rbac', re.IGNORECASE)
_CREDENTIAL_NAME_RE = re.compile(
    r'authoriz|auth|token|jwt|session|cookie|bearer|api[_-]?key|apikey|credential',
    re.IGNORECASE,
)
_CREDENTIAL_SOURCE_RE = re.compile(r'\breq\.(?:headers|cookies|query|body)\b', re.IGNORECASE)
_VERIFICATION_CALL_RE = re.compile(
    r'jwt\.verify|verifyToken|checkAuth|validateToken|decodeToken|passport\.authenticate|'
    r'loadUser|findByToken|authenticate|authorize|requireRole|checkPermission|hasPermission|hasRole',
    re.IGNORECASE,
)


def _extract_route_blocks(code: str) -> list[_RouteBlock]:
    """Extract simple Express/Router route blocks for block-level heuristics."""
    lines = code.splitlines()
    blocks: list[_RouteBlock] = []
    i = 0
    while i < len(lines):
        stripped = _strip_comments(lines[i]).strip()
        match = _ROUTE_START_RE.search(stripped)
        if not match:
            i += 1
            continue

        method = match.group(1).lower()
        path = match.group(3)
        start_idx = i
        end_idx = i
        brace_depth = 0
        seen_open = False

        for j in range(start_idx, len(lines)):
            text = _strip_comments(lines[j])
            if "{" in text:
                brace_depth += text.count("{")
                seen_open = True
            if "}" in text:
                brace_depth -= text.count("}")
            end_idx = j
            if seen_open and j > start_idx and brace_depth <= 0:
                break
            if not seen_open and j - start_idx >= 10:
                break

        blocks.append(_RouteBlock(
            method=method,
            path=path,
            start_line=start_idx + 1,
            end_line=end_idx + 1,
            code="\n".join(lines[start_idx:end_idx + 1]),
        ))
        i = end_idx + 1
    return blocks


def _route_resource_params(path: str) -> set[str]:
    """Return id-like route parameter names from an Express-style path."""
    return {
        name
        for name in _ROUTE_PARAM_RE.findall(path)
        if _RESOURCE_PARAM_RE.search(name)
    }


def _route_invocation_prefix(block: _RouteBlock) -> str:
    """Return the route invocation prefix up to the handler body opening brace."""
    parts: list[str] = []
    for line in block.code.splitlines():
        cleaned = _strip_comments(line)
        parts.append(cleaned)
        if "{" in cleaned or len(parts) >= 4:
            break
    return "\n".join(parts)


def _route_auth_labels(block: _RouteBlock) -> tuple[str, ...]:
    """Return auth middleware names mentioned in the route invocation."""
    labels: list[str] = []
    for match in _AUTH_MIDDLEWARE_RE.finditer(_route_invocation_prefix(block)):
        label = match.group(0)
        if label not in labels:
            labels.append(label)
    return tuple(labels)


def _route_privilege_labels(block: _RouteBlock) -> tuple[str, ...]:
    """Return privilege middleware names mentioned in the route invocation."""
    labels: list[str] = []
    for match in _PRIVILEGE_MIDDLEWARE_RE.finditer(_route_invocation_prefix(block)):
        label = match.group(0)
        if label not in labels:
            labels.append(label)
    return tuple(labels)


def _is_public_route(path: str) -> bool:
    """Return True when a route path looks intentionally public."""
    return bool(_PUBLIC_ROUTE_RE.search(path))


def _is_admin_route(path: str) -> bool:
    """Return True when a route path looks administrative or privileged."""
    return bool(_ADMIN_ROUTE_RE.search(path))


def _route_base_trace(block: _RouteBlock, resource_params: set[str], auth_labels: tuple[str, ...]) -> tuple[TraceFrame, ...]:
    """Build a route-oriented base trace for access-control findings."""
    trace: tuple[TraceFrame, ...] = ()
    trace = _append_trace(trace, "source", f"route `{block.path}` method `{block.method.upper()}`", line=block.start_line)
    for param in sorted(resource_params):
        trace = _append_trace(trace, "source", f"resource parameter `{param}`", line=block.start_line)
    for label in auth_labels:
        trace = _append_trace(trace, "check", f"auth middleware `{label}`", line=block.start_line)
    return trace


def _extract_principal_aliases(code: str) -> set[str]:
    """Return local aliases assigned from the current principal/session context."""
    aliases: set[str] = set()
    for line in code.splitlines():
        stripped = _strip_comments(line).strip()
        match = _ASSIGNMENT_RE.match(stripped)
        if not match:
            continue
        target, expr = match.groups()
        if _PRINCIPAL_REF_RE.search(expr):
            aliases.add(target)
    return aliases


def _line_has_owner_guard(line: str, principal_aliases: set[str]) -> bool:
    """Return True when a line looks like an ownership or tenant scoping guard."""
    stripped = _strip_comments(line).strip()
    if not stripped or not _OWNERSHIP_KEY_RE.search(stripped):
        return False
    has_principal = bool(_PRINCIPAL_REF_RE.search(stripped))
    if not has_principal:
        has_principal = any(re.search(rf'\b{re.escape(alias)}\b', stripped) for alias in principal_aliases)
    if not has_principal:
        return False
    has_structure = bool(re.search(r'\bif\b|where\s*:|filter|findOne|findUnique|findFirst|403|forbid|throw', stripped, re.IGNORECASE))
    has_compare = any(op in stripped for op in ('===', '!==', '==', '!='))
    return has_structure or has_compare


def _block_has_ownership_guard(block: _RouteBlock) -> bool:
    """Return True when a route block appears to scope access by ownership."""
    principal_aliases = _extract_principal_aliases(block.code)
    return any(_line_has_owner_guard(line, principal_aliases) for line in block.code.splitlines())


def _line_has_privilege_guard(line: str, principal_aliases: set[str]) -> bool:
    """Return True when a line checks admin/role/permission state before access."""
    stripped = _strip_comments(line).strip()
    if not stripped or not _PRIVILEGE_KEY_RE.search(stripped):
        return False
    if _PRIVILEGE_MIDDLEWARE_RE.search(stripped):
        return True
    has_principal = bool(_PRINCIPAL_REF_RE.search(stripped))
    if not has_principal:
        has_principal = any(re.search(rf'\b{re.escape(alias)}\b', stripped) for alias in principal_aliases)
    if not has_principal:
        return False
    has_structure = bool(re.search(r'\bif\b|403|forbid|throw|return\b', stripped, re.IGNORECASE))
    has_compare = any(op in stripped for op in ('===', '!==', '==', '!='))
    return has_structure or has_compare


def _block_has_privilege_guard(block: _RouteBlock) -> bool:
    """Return True when a route block appears to enforce privileged access."""
    principal_aliases = _extract_principal_aliases(block.code)
    return any(_line_has_privilege_guard(line, principal_aliases) for line in block.code.splitlines())


def _route_looks_sensitive(block: _RouteBlock, resource_params: set[str]) -> bool:
    """Return True when a route is likely to need auth due to path or behavior."""
    if _is_admin_route(block.path) or block.method in {"post", "put", "patch", "delete"} or resource_params:
        return True
    for line in block.code.splitlines():
        stripped = _strip_comments(line).strip()
        if not stripped:
            continue
        if _LOOKUP_SINK_RE.search(stripped) or _DIRECT_MUTATION_SINK_RE.search(stripped):
            return True
    return False


def _extract_credential_traces(block: _RouteBlock) -> dict[str, tuple[TraceFrame, ...]]:
    """Return auth-credential aliases sourced from req.headers/cookies/query/body."""
    traces: dict[str, tuple[TraceFrame, ...]] = {}
    lines = block.code.splitlines()

    for _ in range(3):
        changed = False
        for lineno, line in enumerate(lines, block.start_line):
            stripped = _strip_comments(line).strip()
            if not stripped or _COMMENT_LINE_RE.match(stripped):
                continue
            match = _ASSIGNMENT_RE.match(stripped)
            if not match:
                continue
            target, expr = match.groups()
            if target in traces:
                continue
            if _CREDENTIAL_SOURCE_RE.search(expr) and _CREDENTIAL_NAME_RE.search(expr + " " + target):
                traces[target] = (
                    TraceFrame(kind="source", label=f"credential source `{expr[:80]}`", line=lineno),
                    TraceFrame(kind="propagator", label=f"assign to `{target}`", line=lineno),
                )
                changed = True
                continue
            if not _CREDENTIAL_NAME_RE.search(target):
                continue
            referenced = [name for name in traces if re.search(rf'\b{re.escape(name)}\b', expr)]
            if referenced:
                trace = traces[referenced[0]]
                if re.search(r'\b\w+\s*\(', expr):
                    trace = _append_trace(trace, "helper", f"through `{expr[:80]}`", line=lineno)
                else:
                    trace = _append_trace(trace, "propagator", f"via `{expr[:80]}`", line=lineno)
                trace = _append_trace(trace, "propagator", f"assign to `{target}`", line=lineno)
                traces[target] = trace
                changed = True
        if not changed:
            break

    return traces


def _presence_only_gate(
    line: str,
    *,
    line_no: int,
    credential_traces: dict[str, tuple[TraceFrame, ...]],
) -> tuple[str, tuple[TraceFrame, ...]] | None:
    """Return the presence-only auth gate on a line and its credential trace."""
    stripped = _strip_comments(line).strip()
    if not stripped or not stripped.startswith("if"):
        return None

    alias_match = re.search(r'\bif\s*\(\s*(!?\s*([A-Za-z_$][\w$]*))\s*\)', stripped)
    if alias_match:
        alias = alias_match.group(2)
        if alias in credential_traces:
            return (f"if ({alias_match.group(1).strip()})", credential_traces[alias])

    direct_match = re.search(
        r'\bif\s*\(\s*(!?\s*(req\.(?:headers|cookies|query|body)(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])))\s*\)',
        stripped,
        re.IGNORECASE,
    )
    if direct_match and _CREDENTIAL_NAME_RE.search(direct_match.group(2)):
        trace = (
            TraceFrame(kind="source", label=f"credential source `{direct_match.group(2)[:80]}`", line=line_no),
        )
        return (f"if ({direct_match.group(1).strip()})", trace)

    return None


def _first_presence_only_gate(block: _RouteBlock) -> tuple[int, str, tuple[TraceFrame, ...]] | None:
    """Return the first presence-only auth gate in a route block, if any."""
    credential_traces = _extract_credential_traces(block)
    for lineno, line in enumerate(block.code.splitlines(), block.start_line):
        gate = _presence_only_gate(line, line_no=lineno, credential_traces=credential_traces)
        if gate:
            return (lineno, gate[0], gate[1])
    return None


def _block_has_verification(block: _RouteBlock) -> bool:
    """Return True when a route block appears to verify credentials or principal state."""
    return bool(_VERIFICATION_CALL_RE.search(block.code))


def _trace_mentions_route_param(trace: tuple[TraceFrame, ...], resource_params: set[str]) -> bool:
    """Return True when a taint trace appears to originate from the route resource parameter."""
    labels = " ".join(frame.label.lower() for frame in trace)
    if 'req.params.' in labels:
        return True
    return any(param.lower() in labels for param in resource_params)


def _find_route_resource_reference(
    line: str,
    *,
    resource_params: set[str],
    taint_traces: dict[str, tuple[TraceFrame, ...]],
    line_no: int,
    route_line: int,
) -> tuple[str, tuple[TraceFrame, ...]] | None:
    """Return the first route resource reference on a line and its supporting trace."""
    for param in sorted(resource_params):
        for source in ("params", "query", "body"):
            ref = f"req.{source}.{param}"
            if ref in line:
                return (
                    ref,
                    (
                        TraceFrame(kind="source", label=f"resource parameter `{param}`", line=route_line),
                        TraceFrame(kind="propagator", label=f"direct use `{ref}`", line=line_no),
                    ),
                )
    for var, trace in taint_traces.items():
        if re.search(rf'\b{re.escape(var)}\b', line) and _trace_mentions_route_param(trace, resource_params):
            return (var, trace)
    return None


def _check_route_idor(code: str) -> list[Finding]:
    """Detect Express-style IDOR lookups by route ID without ownership scoping."""
    findings: list[Finding] = []
    for block in _extract_route_blocks(code):
        resource_params = _route_resource_params(block.path)
        if not resource_params:
            continue
        auth_labels = _route_auth_labels(block)
        has_auth = bool(auth_labels)
        if _block_has_ownership_guard(block):
            continue
        taint_traces = _extract_taint_traces(block.code, line_offset=block.start_line - 1)
        base_trace = _route_base_trace(block, resource_params, auth_labels)

        for lineno, line in enumerate(block.code.splitlines(), block.start_line):
            stripped = _strip_comments(line).strip()
            if not stripped or _COMMENT_LINE_RE.match(stripped):
                continue
            if not _LOOKUP_SINK_RE.search(stripped):
                continue
            ref = _find_route_resource_reference(
                stripped,
                resource_params=resource_params,
                taint_traces=taint_traces,
                line_no=lineno,
                route_line=block.start_line,
            )
            if not ref:
                continue
            _, ref_trace = ref
            trace = _merge_traces(base_trace, ref_trace)
            if not has_auth:
                trace = _append_trace(trace, "gap", "no auth middleware detected", line=block.start_line)
            trace = _append_trace(trace, "gap", "no ownership guard detected", line=block.start_line)
            trace = _append_trace(trace, "sink", f"resource lookup `{stripped[:80]}`", line=lineno)
            findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL if not has_auth else Severity.HIGH,
                title=(
                    "CWE-639: Public IDOR via route parameter"
                    if not has_auth else
                    "CWE-639: IDOR via route parameter with no ownership check"
                ) + f" at line {lineno}",
                description=(
                    f"Route `{block.path}` performs a resource lookup at L{lineno} using a user-controlled "
                    f"route identifier without "
                    + ("authentication or " if not has_auth else "")
                    + "ownership scoping. An attacker can access another user's record by changing the ID."
                ),
                line=lineno,
                suggestion=(
                    "Scope lookups by owner/tenant as well as resource ID, for example "
                    "`where: { id: postId, ownerId: req.user.id }`, and protect the route with auth middleware."
                ),
                cwe="CWE-639",
                agent="js-analyzer",
                rule_id="JS-033",
                confidence=0.92,
                analysis_kind="route-heuristic",
                trace=trace,
            ))
            break
    return findings


def _check_route_missing_auth(code: str) -> list[Finding]:
    """Detect sensitive Express routes that have no auth middleware or inline auth logic."""
    findings: list[Finding] = []
    for block in _extract_route_blocks(code):
        resource_params = _route_resource_params(block.path)
        if _is_public_route(block.path):
            continue
        if _route_auth_labels(block):
            continue
        if _block_has_verification(block) or _first_presence_only_gate(block):
            continue
        if not _route_looks_sensitive(block, resource_params):
            continue

        trace = _route_base_trace(block, resource_params, ())
        trace = _append_trace(trace, "gap", "no auth middleware detected", line=block.start_line)
        if _is_admin_route(block.path):
            severity = Severity.CRITICAL
            sink_label = "admin route reachable without auth"
            title = f"CWE-862: Missing auth on admin route at line {block.start_line}"
            description = (
                f"Admin route `{block.path}` is reachable without authentication. Any unauthenticated caller "
                f"can invoke this privileged endpoint."
            )
        elif block.method in {"post", "put", "patch", "delete"}:
            severity = Severity.HIGH
            sink_label = f"mutating route `{block.method.upper()}` reachable without auth"
            title = f"CWE-862: Missing auth on mutating route at line {block.start_line}"
            description = (
                f"Route `{block.path}` uses HTTP {block.method.upper()} with no authentication middleware. "
                f"State-changing endpoints should require an authenticated caller."
            )
        else:
            severity = Severity.HIGH
            sink_label = "resource route reachable without auth"
            title = f"CWE-862: Missing auth on resource route at line {block.start_line}"
            description = (
                f"Route `{block.path}` accesses a resource identifier without authentication middleware. "
                f"An attacker can reach this resource-specific endpoint anonymously."
            )
        trace = _append_trace(trace, "sink", sink_label, line=block.start_line)
        findings.append(Finding(
            category="security",
            severity=severity,
            title=title,
            description=description,
            line=block.start_line,
            suggestion=(
                "Protect this route with auth middleware such as `requireAuth`, `passport.authenticate(...)`, "
                "or a verified JWT/session guard before the handler executes."
            ),
            cwe="CWE-862",
            agent="js-analyzer",
            rule_id="JS-034",
            confidence=0.95,
            analysis_kind="route-heuristic",
            trace=trace,
        ))
    return findings


def _check_admin_broken_access_control(code: str) -> list[Finding]:
    """Detect admin routes that authenticate users but never verify privileged roles."""
    findings: list[Finding] = []
    for block in _extract_route_blocks(code):
        if not _is_admin_route(block.path):
            continue
        auth_labels = _route_auth_labels(block)
        if not auth_labels:
            continue
        privilege_labels = _route_privilege_labels(block)
        if privilege_labels or _block_has_privilege_guard(block):
            continue

        trace = _route_base_trace(block, _route_resource_params(block.path), auth_labels)
        trace = _append_trace(trace, "gap", "no privilege guard detected", line=block.start_line)
        trace = _append_trace(trace, "sink", "admin route reachable after auth only", line=block.start_line)
        findings.append(Finding(
            category="security",
            severity=Severity.CRITICAL,
            title=f"CWE-285: Broken access control on admin route at line {block.start_line}",
            description=(
                f"Admin route `{block.path}` authenticates the caller but never checks for an admin/role/permission "
                f"guard. Any authenticated user may be able to reach privileged functionality."
            ),
            line=block.start_line,
            suggestion=(
                "Add a privilege middleware such as `requireAdmin`, `requireRole('admin')`, or an explicit "
                "`if (req.user.role !== 'admin') return res.status(403)...` guard."
            ),
            cwe="CWE-285",
            agent="js-analyzer",
            rule_id="JS-035",
            confidence=0.9,
            analysis_kind="route-heuristic",
            trace=trace,
        ))
    return findings


def _check_route_auth_bypass(code: str) -> list[Finding]:
    """Detect custom auth gates that only check credential presence, not validity."""
    findings: list[Finding] = []
    for block in _extract_route_blocks(code):
        resource_params = _route_resource_params(block.path)
        if _is_public_route(block.path):
            continue
        if _route_auth_labels(block):
            continue
        if _block_has_verification(block):
            continue
        if not _route_looks_sensitive(block, resource_params):
            continue

        gate = _first_presence_only_gate(block)
        if not gate:
            continue
        gate_line, gate_label, credential_trace = gate
        trace = _merge_traces(_route_base_trace(block, resource_params, ()), credential_trace)
        trace = _append_trace(trace, "gap", "credential never verified", line=gate_line)
        trace = _append_trace(trace, "sink", f"presence-only gate `{gate_label}`", line=gate_line)
        findings.append(Finding(
            category="security",
            severity=Severity.CRITICAL if _is_admin_route(block.path) else Severity.HIGH,
            title=f"CWE-287: Auth bypass via presence-only credential check at line {gate_line}",
            description=(
                f"Route `{block.path}` checks only whether a credential-like value exists before allowing access. "
                f"Any non-empty header/cookie/query value can satisfy this gate if the token is never verified."
            ),
            line=gate_line,
            suggestion=(
                "Verify the credential cryptographically (for example `jwt.verify(token, secret)` or a dedicated "
                "`verifyToken` helper) and gate access on the verified user/principal, not raw token presence."
            ),
            cwe="CWE-287",
            agent="js-analyzer",
            rule_id="JS-036",
            confidence=0.9,
            analysis_kind="route-heuristic",
            trace=trace,
        ))
    return findings


def _check_route_missing_ownership_mutation(code: str) -> list[Finding]:
    """Detect authenticated resource mutations that lack ownership verification."""
    findings: list[Finding] = []
    for block in _extract_route_blocks(code):
        resource_params = _route_resource_params(block.path)
        if not resource_params or block.method not in {"post", "put", "patch", "delete"}:
            continue
        auth_labels = _route_auth_labels(block)
        if not auth_labels or _block_has_ownership_guard(block):
            continue

        taint_traces = _extract_taint_traces(block.code, line_offset=block.start_line - 1)
        base_trace = _route_base_trace(block, resource_params, auth_labels)
        resource_vars: dict[str, tuple[int, str, tuple[TraceFrame, ...]]] = {}

        for lineno, line in enumerate(block.code.splitlines(), block.start_line):
            stripped = _strip_comments(line).strip()
            if not stripped:
                continue
            match = _ASSIGNMENT_RE.match(stripped)
            if not match:
                continue
            target, expr = match.groups()
            if not _LOOKUP_SINK_RE.search(expr):
                continue
            ref = _find_route_resource_reference(
                expr,
                resource_params=resource_params,
                taint_traces=taint_traces,
                line_no=lineno,
                route_line=block.start_line,
            )
            if not ref:
                continue
            _, ref_trace = ref
            lookup_trace = _merge_traces(ref_trace, (TraceFrame(kind="check", label=f"loaded resource `{expr[:80]}`", line=lineno),))
            resource_vars[target] = (lineno, expr[:80], lookup_trace)

        for lineno, line in enumerate(block.code.splitlines(), block.start_line):
            stripped = _strip_comments(line).strip()
            if not stripped or _COMMENT_LINE_RE.match(stripped):
                continue
            if lineno == block.start_line and _ROUTE_START_RE.search(stripped):
                continue
            if not _DIRECT_MUTATION_SINK_RE.search(stripped):
                continue

            ref_trace: tuple[TraceFrame, ...] = ()
            mutation_label = stripped[:80]
            inst_match = _INSTANCE_MUTATION_RE.search(stripped)
            if inst_match:
                resource_var = inst_match.group(1)
                if resource_var in resource_vars:
                    _, lookup_label, lookup_trace = resource_vars[resource_var]
                    ref_trace = lookup_trace
                    mutation_label = f"{resource_var}.{inst_match.group(2)}()"
                else:
                    continue
            else:
                ref = _find_route_resource_reference(
                    stripped,
                    resource_params=resource_params,
                    taint_traces=taint_traces,
                    line_no=lineno,
                    route_line=block.start_line,
                )
                if not ref:
                    continue
                _, ref_trace = ref

            trace = _merge_traces(base_trace, ref_trace)
            trace = _append_trace(trace, "gap", "no ownership guard detected before mutation", line=block.start_line)
            trace = _append_trace(trace, "sink", f"mutation `{mutation_label}`", line=lineno)
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-285: Missing ownership check before mutation at line {lineno}",
                description=(
                    f"Authenticated route `{block.path}` mutates a resource at L{lineno} using a user-controlled "
                    f"route identifier without verifying the caller owns that resource."
                ),
                line=lineno,
                suggestion=(
                    "Load the record with an owner/tenant filter before mutating it, for example "
                    "`where: { id: postId, ownerId: req.user.id }`, or block with a 403 ownership check."
                ),
                cwe="CWE-285",
                agent="js-analyzer",
                rule_id="JS-037",
                confidence=0.91,
                analysis_kind="route-heuristic",
                trace=trace,
            ))
            break
    return findings


def _first_referenced_taint_var(line: str, taint_traces: dict[str, tuple[TraceFrame, ...]]) -> str | None:
    """Return the first tainted variable name referenced on the given line."""
    for var in taint_traces:
        if re.search(rf'\b{re.escape(var)}\b', line):
            return var
    return None


def _make_taint_calls_finding(
    lineno: int, line: str, rule_id: str, cwe: str, title_prefix: str, desc: str, suggestion: str,
    severity: Severity,
    trace: tuple[TraceFrame, ...] = (),
) -> Finding:
    return Finding(
        category="security", severity=severity,
        title=f"{title_prefix} at line {lineno}",
        description=desc.format(line=lineno, snippet=line.strip()[:90]),
        line=lineno, suggestion=suggestion,
        rule_id=rule_id,
        cwe=cwe, agent="js-analyzer",
        confidence=0.93,
        analysis_kind="taint-flow",
        trace=trace,
    )


def _check_taint_path_traversal(code: str, taint_traces: dict[str, tuple[TraceFrame, ...]]) -> list[Finding]:
    """Detect fs.*() calls using variables that were assigned from req.*."""
    if not taint_traces:
        return []
    var_pat = "|".join(re.escape(v) for v in taint_traces)
    pattern = re.compile(
        rf'(?:fs\.|path\.resolve|path\.join)\w*\s*\([^)]*(?:{var_pat})',
        re.IGNORECASE,
    )
    findings: list[Finding] = []
    for lineno, line in enumerate(code.splitlines(), 1):
        if _COMMENT_LINE_RE.match(line.strip()):
            continue
        if pattern.search(line):
            var_name = _first_referenced_taint_var(line, taint_traces)
            trace = taint_traces.get(var_name or "", ())
            trace = _append_trace(trace, "sink", "sink `fs/path operation`", line=lineno)
            findings.append(_make_taint_calls_finding(
                lineno, line, "JS-038", "CWE-22",
                "CWE-22: Path traversal via tainted variable",
                "File-system operation uses `{snippet}` (L{line}) with a variable that came from "
                "user-controlled `req.*` input. An attacker can use `../` sequences.",
                "Sanitize with `path.basename()` and verify the resolved path starts with BASE.",
                Severity.HIGH,
                trace=trace,
            ))
    return findings


def _check_taint_redirect(code: str, taint_traces: dict[str, tuple[TraceFrame, ...]]) -> list[Finding]:
    """Detect res.redirect() calls using variables from req.*."""
    if not taint_traces:
        return []
    var_pat = "|".join(re.escape(v) for v in taint_traces)
    pattern = re.compile(rf'res\.redirect\s*\([^)]*(?:{var_pat})', re.IGNORECASE)
    findings: list[Finding] = []
    for lineno, line in enumerate(code.splitlines(), 1):
        if _COMMENT_LINE_RE.match(line.strip()):
            continue
        if pattern.search(line):
            var_name = _first_referenced_taint_var(line, taint_traces)
            trace = taint_traces.get(var_name or "", ())
            trace = _append_trace(trace, "sink", "sink `res.redirect()`", line=lineno)
            findings.append(_make_taint_calls_finding(
                lineno, line, "JS-039", "CWE-601",
                "CWE-601: Open redirect via tainted variable",
                "`res.redirect()` at L{line} uses a variable sourced from `req.*`: `{snippet}`. "
                "An attacker can redirect victims to a phishing site.",
                "Validate the redirect target against an allowlist of permitted paths.",
                Severity.HIGH,
                trace=trace,
            ))
    return findings


def _check_taint_ssrf(code: str, taint_traces: dict[str, tuple[TraceFrame, ...]]) -> list[Finding]:
    """Detect HTTP client calls using variables from req.*."""
    if not taint_traces:
        return []
    var_pat = "|".join(re.escape(v) for v in taint_traces)
    pattern = re.compile(
        rf'(?:fetch|axios\.(?:get|post)|request|got|needle|http\.get|https\.get)\s*\([^)]*(?:{var_pat})',
        re.IGNORECASE,
    )
    findings: list[Finding] = []
    for lineno, line in enumerate(code.splitlines(), 1):
        if _COMMENT_LINE_RE.match(line.strip()):
            continue
        if pattern.search(line):
            var_name = _first_referenced_taint_var(line, taint_traces)
            trace = taint_traces.get(var_name or "", ())
            trace = _append_trace(trace, "sink", "sink `HTTP client call`", line=lineno)
            findings.append(_make_taint_calls_finding(
                lineno, line, "JS-040", "CWE-918",
                "CWE-918: SSRF via tainted variable",
                "HTTP client call at L{line} uses a URL from user-controlled `req.*`: `{snippet}`. "
                "An attacker can target internal services (cloud metadata, Redis, etc.).",
                "Validate URL hostname against an explicit ALLOWED_HOSTS allowlist. "
                "Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x).",
                Severity.HIGH,
                trace=trace,
            ))
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Deduplication
# ──────────────────────────────────────────────────────────────────────────────

def _dedup(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, int | None]] = set()
    out: list[Finding] = []
    for f in sorted(findings, key=lambda x: x.severity.sort_key):
        key = (f.title.lower()[:60], f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def analyze_js(code: str, filename: str = "") -> AnalysisResult:
    """
    Analyze JavaScript/TypeScript source code for security vulnerabilities.

    Args:
        code:     Full source code as a string.
        filename: Optional file path for reporting.

    Returns:
        AnalysisResult with all findings sorted by severity.
    """
    result = AnalysisResult(
        file_path=filename,
        language="javascript",
        lines_scanned=len(code.splitlines()),
    )
    all_findings: list[Finding] = []

    # Run all rule-based checks
    for rule in _RULES:
        try:
            all_findings.extend(rule.check(code, filename))
        except (ValueError, TypeError, RecursionError, re.error) as exc:  # noqa: BLE001
            _log.debug("ansede-static: rule %r failed on %r: %s", rule, filename, exc, exc_info=True)

    # Run context-aware checks
    for checker in (
        _check_no_rate_limit,
        _check_hardcoded_jwt_secret,
        _check_sensitive_console_log,
        _check_dangerous_object_merge,
        _check_route_missing_auth,
        _check_admin_broken_access_control,
        _check_route_auth_bypass,
        _check_route_idor,
        _check_route_missing_ownership_mutation,
    ):
        try:
            all_findings.extend(checker(code))
        except (ValueError, TypeError, RecursionError, re.error) as exc:  # noqa: BLE001
            _log.debug("ansede-static: %s failed on %r: %s", checker.__name__, filename, exc, exc_info=True)

    # Run taint-variable indirect checks (two-pass: extract vars, then check sinks)
    try:
        taint_traces = _extract_taint_traces(code)
        for taint_checker in (
            _check_taint_path_traversal,
            _check_taint_redirect,
            _check_taint_ssrf,
        ):
            all_findings.extend(taint_checker(code, taint_traces))
    except (ValueError, TypeError, RecursionError, re.error) as exc:  # noqa: BLE001
        _log.debug("ansede-static: taint checks failed on %r: %s", filename, exc, exc_info=True)

    deduped = _dedup(all_findings)

    # ── Filter out inline-suppressed findings ─────────────────────────────
    src_lines = code.splitlines()
    filtered: list[Finding] = []
    for f in deduped:
        if f.line and 0 < f.line <= len(src_lines):
            m = _SUPPRESSION_RE.search(src_lines[f.line - 1])
            if m:
                suppressed = m.group(1)
                if not suppressed or (f.cwe and f.cwe in suppressed):
                    continue
        filtered.append(f)

    result.findings = filtered
    return result


def analyze_file(path: str | Path) -> AnalysisResult:
    """Convenience wrapper that reads a file then calls analyze_js."""
    p = Path(path)
    code = p.read_text(encoding="utf-8", errors="replace")
    return analyze_js(code, filename=str(p))
