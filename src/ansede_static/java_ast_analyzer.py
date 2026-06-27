"""
java_ast_analyzer.py — Ansede Static tree-sitter Java analysis engine.

Replaces regex structural heuristics with accurate tree-sitter AST parsing.
Provides: method extraction, call-graph construction, annotation-aware routing,
taint-source → sink tracking, and framework-aware analysis (Spring, JAX-RS,
Micronaut, Quarkus).

Architecture mirrors js_ast_analyzer.py: parse → extract → match → report.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tree_sitter import Language, Parser, Node
import tree_sitter_java as tsjava

from ansede_static._types import AnalysisResult, Finding, Severity, TraceFrame

_log = logging.getLogger(__name__)

# ── tree-sitter setup ───────────────────────────────────────────────────────
JAVA_LANGUAGE = Language(tsjava.language())
_JAVA_PARSER = Parser(JAVA_LANGUAGE)

# ── Constants ───────────────────────────────────────────────────────────────
_ROUTE_ANNOTATIONS: frozenset[str] = frozenset({
    "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
    "RequestMapping",
    "GET", "POST", "PUT", "DELETE", "PATCH", "Path",
    "Get", "Post", "Put", "Delete", "Patch",
})
_MUTATING_ANNOTATIONS: frozenset[str] = frozenset({
    "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
    "POST", "PUT", "DELETE", "PATCH",
    "Post", "Put", "Delete", "Patch",
})
_AUTH_ANNOTATIONS: frozenset[str] = frozenset({
    "PreAuthorize", "Secured", "RolesAllowed",
    "Authenticated", "PermitAll", "DenyAll",
})

# ── Taint source patterns (user input) ──────────────────────────────────────
_REQUEST_TAINT_METHODS: frozenset[str] = frozenset({
    "getParameter", "getQueryString", "getHeader",
    "getCookie", "getRequestBody", "getPathParameter",
    "getFormParam", "getQueryParam", "getMatrixParam",
    "getInputStream", "getReader",
})

# ── Sink patterns by CWE ────────────────────────────────────────────────────
_SQLI_METHODS: frozenset[str] = frozenset({
    "createQuery", "executeQuery", "executeUpdate",
    "createNativeQuery",
})
_SQLI_CLASSES: frozenset[str] = frozenset({
    "JdbcTemplate",
})

_CMD_EXEC_CLASSES: frozenset[str] = frozenset({
    "Runtime",
})
_CMD_EXEC_METHODS: frozenset[str] = frozenset({
    "exec",
})
_PROCESS_BUILDER_CLASSES: frozenset[str] = frozenset({
    "ProcessBuilder",
})

_WEAK_CRYPTO_ALGOS: frozenset[str] = frozenset({
    "MD5", "SHA1", "SHA-1", "DES", "RC4", "RC2", "Blowfish",
})

_SSRF_CLASSES: frozenset[str] = frozenset({
    "URL", "HttpURLConnection", "HttpClient", "RestTemplate",
    "WebClient", "OkHttpClient",
})

_REDIRECT_METHODS: frozenset[str] = frozenset({
    "sendRedirect",
})

_XSS_SINK_METHODS: frozenset[str] = frozenset({
    "getWriter", "getOutputStream",
})

# Receiver names that indicate HTTP response context (for XSS detection)
_XSS_RESPONSE_RECEIVERS: frozenset[str] = frozenset({
    "response", "res", "resp", "httpresponse", "servletresponse",
    "httpresponse", "writer", "printwriter", "outputstream",
})

_PATH_TRAVERSAL_CLASSES: frozenset[str] = frozenset({
    "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
    "RandomAccessFile", "File",
})
_PATH_TRAVERSAL_METHODS: frozenset[str] = frozenset({
    "Paths.get",
})

# ── Data classes ────────────────────────────────────────────────────────────


@dataclass
class _JavaCall:
    """A method invocation extracted from the AST."""
    callee: str
    arguments: list[str]
    line: int
    raw: str = ""
    receiver: str = ""  # e.g., "Runtime" in Runtime.getRuntime().exec()


@dataclass
class _JavaMethod:
    """A method declaration extracted from the AST."""
    name: str
    start_line: int
    body: str
    annotations: list[str] = field(default_factory=list)
    route_paths: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    is_public: bool = False
    has_auth: bool = False


# ── AST helpers ─────────────────────────────────────────────────────────────


def _node_text(node: Node, source: bytes) -> str:
    """Get the source text for a tree-sitter node."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _find_all(node: Node, type_name: str) -> list[Node]:
    """Recursively find all nodes of a given type."""
    result: list[Node] = []
    if node.type == type_name:
        result.append(node)
    for child in node.children:
        result.extend(_find_all(child, type_name))
    return result


def _find_child(node: Node, type_name: str) -> Node | None:
    """Find the first direct child of a given type."""
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def _find_descendant(node: Node, type_name: str) -> Node | None:
    """Find the first descendant of a given type (depth-first)."""
    if node.type == type_name:
        return node
    for child in node.children:
        result = _find_descendant(child, type_name)
        if result is not None:
            return result
    return None


def _collect_method_invocations(node: Node, source: bytes) -> list[_JavaCall]:
    """Collect all method invocations from a subtree."""
    calls: list[_JavaCall] = []
    if node.type == "method_invocation":
        calls.append(_parse_method_invocation(node, source))
    for child in node.children:
        calls.extend(_collect_method_invocations(child, source))
    return calls


def _parse_method_invocation(node: Node, source: bytes) -> _JavaCall:
    """Parse a method_invocation AST node into a _JavaCall."""
    arguments: list[str] = []
    callee = ""
    receiver = ""

    # Collect all identifiers — the last one before argument_list is the method name
    identifiers: list[str] = []
    has_nested_invocation = False
    for child in node.children:
        if child.type == "identifier":
            identifiers.append(_node_text(child, source))
        elif child.type == "method_invocation":
            has_nested_invocation = True
            # For chained calls like Runtime.getRuntime().exec():
            # extract the first identifier from the nested invocation as the receiver
            nested_ids: list[str] = []
            for nc in child.children:
                if nc.type == "identifier":
                    nested_ids.append(_node_text(nc, source))
            if nested_ids:
                receiver = nested_ids[0]  # e.g., "Runtime"

    # Method name is the last identifier, receiver from first if not already set
    if identifiers:
        callee = identifiers[-1]
        if not receiver and len(identifiers) >= 2:
            receiver = identifiers[-2]

    # Find arguments
    args_node = _find_child(node, "argument_list")
    if args_node is not None:
        for child in args_node.children:
            if child.type not in ("(", ")", ","):
                arguments.append(_node_text(child, source).strip())

    return _JavaCall(
        callee=callee,
        arguments=arguments,
        line=node.start_point[0] + 1,
        raw=_node_text(node, source),
        receiver=receiver,
    )


def _parse_object_creation(node: Node, source: bytes) -> tuple[str, list[str], int]:
    """Parse object_creation_expression: returns (class_name, arguments, line)."""
    class_name = ""
    arguments: list[str] = []

    type_node = _find_child(node, "type_identifier")
    if type_node is None:
        type_node = _find_child(node, "scoped_type_identifier")
    if type_node is not None:
        class_name = _node_text(type_node, source)

    args_node = _find_child(node, "argument_list")
    if args_node is not None:
        for child in args_node.children:
            if child.type not in ("(", ")", ","):
                arguments.append(_node_text(child, source).strip())

    return class_name, arguments, node.start_point[0] + 1


def _collect_object_creations(node: Node, source: bytes) -> list[tuple[str, list[str], int]]:
    """Collect all object_creation_expression nodes."""
    creations: list[tuple[str, list[str], int]] = []
    if node.type == "object_creation_expression":
        creations.append(_parse_object_creation(node, source))
    for child in node.children:
        creations.extend(_collect_object_creations(child, source))
    return creations


def _parse_method_declaration(node: Node, source: bytes) -> _JavaMethod:
    """Parse a method_declaration AST node."""
    name = ""
    body = ""
    start_line = node.start_point[0] + 1
    annotations: list[str] = []
    route_paths: list[str] = []
    params: list[str] = []
    is_public = False
    has_auth = False

    for child in node.children:
        if child.type == "identifier":
            name = _node_text(child, source)
        elif child.type == "block":
            body = _node_text(child, source)
        elif child.type == "modifiers":
            mod_text = _node_text(child, source)
            if "public" in mod_text:
                is_public = True
            # Extract annotations from modifiers
            for mod_child in child.children:
                if mod_child.type in ("marker_annotation", "annotation"):
                    annotations.append(_node_text(mod_child, source))
        elif child.type == "formal_parameters":
            for param_child in child.children:
                if param_child.type == "formal_parameter":
                    # Find the parameter name identifier — it's the LAST direct
                    # identifier child, not one nested inside annotations/modifiers
                    param_identifiers = [c for c in param_child.children if c.type == "identifier"]
                    if param_identifiers:
                        params.append(_node_text(param_identifiers[-1], source))

    # Look for annotations in the parent (class_declaration) or sibling context
    # In tree-sitter, annotations on methods appear before the method_declaration
    # as siblings within the class body. We handle this during _collect_methods.

    # Check for route annotations
    for ann in annotations:
        ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0]
        if ann_short in _ROUTE_ANNOTATIONS:
            # Extract path from annotation value
            path_matches = re.findall(r'"([^"]*)"', ann)
            route_paths.extend(path_matches)

    # Check for auth annotations
    for ann in annotations:
        ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0]
        if ann_short in _AUTH_ANNOTATIONS:
            has_auth = True

    return _JavaMethod(
        name=name,
        start_line=start_line,
        body=body,
        annotations=annotations,
        route_paths=route_paths,
        params=params,
        is_public=is_public,
        has_auth=has_auth,
    )


def _collect_methods(source: bytes, tree: Node) -> list[_JavaMethod]:
    """Collect all method declarations with their annotations from the AST."""
    methods: list[_JavaMethod] = []
    root = tree.root_node

    # Find class_declaration nodes
    for class_node in _find_all(root, "class_declaration"):
        class_body = _find_child(class_node, "class_body")
        if class_body is None:
            continue

        pending_annotations: list[str] = []

        for child in class_body.children:
            text = _node_text(child, source).strip() if child.type != "block" else ""

            # Collect annotations
            if child.type == "marker_annotation" or child.type == "annotation":
                pending_annotations.append(_node_text(child, source))
                continue

            # Method declaration
            if child.type == "method_declaration":
                method = _parse_method_declaration(child, source)
                # Merge pending annotations (from class_body level) with method's own
                method.annotations = pending_annotations + method.annotations
                # Parse route paths and auth from ALL annotations
                for ann in method.annotations:
                    ann_short = ann.rsplit(".", 1)[-1].split("(", 1)[0]
                    if ann_short in _ROUTE_ANNOTATIONS:
                        path_matches = re.findall(r'"([^"]*)"', ann)
                        method.route_paths.extend(path_matches)
                    if ann_short in _AUTH_ANNOTATIONS:
                        method.has_auth = True
                methods.append(method)
                pending_annotations = []
                continue

            # Non-annotation, non-method: reset pending annotations
            if child.type not in ("{", "}", ";", "comment", "block_comment", "line_comment",
                                   "marker_annotation", "annotation"):
                pending_annotations = []

    return methods


def _has_dynamic_input(arguments: list[str], params: list[str]) -> bool:
    """Check if any argument references a method parameter (potential user input)."""
    for arg in arguments:
        arg_clean = arg.strip()
        # Check for string concatenation
        if "+" in arg_clean:
            return True
        # Check for variable references that could be tainted
        for param in params:
            if param in arg_clean:
                return True
        # Check for method calls on arguments (chained input)
        if re.search(r'(?:request|req|body|param|query|header|cookie)\b', arg_clean, re.IGNORECASE):
            return True
    return False


def _has_string_concat(call: _JavaCall) -> bool:
    """Check if any argument involves string concatenation."""
    for arg in call.arguments:
        if "+" in arg:
            return True
        if "String.format" in arg or "StringBuilder" in arg:
            return True
    return False


def _make_finding(
    line: int,
    title: str,
    description: str,
    suggestion: str,
    severity: Severity,
    rule_id: str,
    cwe: str,
    trace: tuple[TraceFrame, ...] = (),
    confidence: float = 0.85,
) -> Finding:
    return Finding(
        category="security",
        severity=severity,
        title=title,
        description=description,
        line=line,
        suggestion=suggestion,
        rule_id=rule_id,
        cwe=cwe,
        agent="java-ast-analyzer",
        confidence=confidence,
        auto_fix="",
        explanation=f"### {cwe}\n\n{description}\n\n**Fix:** {suggestion}",
        analysis_kind="ast",
        trace=list(trace),
    )


# ── Rule checkers ───────────────────────────────────────────────────────────


def _check_sqli(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-89: SQL injection detection."""
    findings: list[Finding] = []
    for method in methods:
        calls = _collect_method_invocations(
            _JAVA_PARSER.parse(method.body.encode("utf-8")).root_node,
            method.body.encode("utf-8"),
        )
        for call in calls:
            # Check SQL execution methods
            if call.callee not in _SQLI_METHODS:
                continue
            if not _has_string_concat(call) and not _has_dynamic_input(call.arguments, method.params):
                continue
            findings.append(_make_finding(
                line=call.line,
                title=f"CWE-89: SQL injection via {call.callee}() at line {call.line}",
                description=f"`{call.callee}()` called with dynamic input at L{call.line}: `{call.raw[:100]}`.",
                suggestion="Use parameterized queries with PreparedStatement or JdbcTemplate with ? placeholders.",
                severity=Severity.CRITICAL,
                rule_id="JV-004",
                cwe="CWE-89",
            ))
    return findings


def _check_cmd_injection(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-78: Command injection detection."""
    findings: list[Finding] = []
    for method in methods:
        # Check method calls
        calls = _collect_method_invocations(
            _JAVA_PARSER.parse(method.body.encode("utf-8")).root_node,
            method.body.encode("utf-8"),
        )
        for call in calls:
            if call.callee == "exec" and call.receiver in ("Runtime", "runtime", "rt"):
                if _has_dynamic_input(call.arguments, method.params):
                    findings.append(_make_finding(
                        line=call.line,
                        title=f"CWE-78: Command injection via Runtime.exec() at line {call.line}",
                        description=f"`Runtime.exec()` called with dynamic input at L{call.line}: `{call.raw[:100]}`.",
                        suggestion="Use ProcessBuilder with a command list, never concatenate user input into shell commands.",
                        severity=Severity.CRITICAL,
                        rule_id="JV-008",
                        cwe="CWE-78",
                    ))

        # Check ProcessBuilder
        creations = _collect_object_creations(
            _JAVA_PARSER.parse(method.body.encode("utf-8")).root_node,
            method.body.encode("utf-8"),
        )
        for class_name, args, line in creations:
            if class_name == "ProcessBuilder" and _has_dynamic_input(args, method.params):
                findings.append(_make_finding(
                    line=line,
                    title=f"CWE-78: Command injection via ProcessBuilder at line {line}",
                    description=f"`new ProcessBuilder()` with dynamic arguments at L{line}.",
                    suggestion="Pass command arguments as a list of hardcoded strings, never with user input concatenation.",
                    severity=Severity.CRITICAL,
                    rule_id="JV-008",
                    cwe="CWE-78",
                ))
    return findings


def _check_weak_crypto(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-328: Weak cryptographic algorithm detection."""
    findings: list[Finding] = []
    for method in methods:
        calls = _collect_method_invocations(
            _JAVA_PARSER.parse(method.body.encode("utf-8")).root_node,
            method.body.encode("utf-8"),
        )
        for call in calls:
            if call.callee != "getInstance":
                continue
            for arg in call.arguments:
                for algo in _WEAK_CRYPTO_ALGOS:
                    if algo.lower() in arg.lower():
                        findings.append(_make_finding(
                            line=call.line,
                            title=f"CWE-328: Weak cryptographic algorithm ({algo}) at line {call.line}",
                            description=f"`MessageDigest.getInstance({algo})` or similar at L{call.line}.",
                            suggestion="Use SHA-256 or stronger. For passwords, use bcrypt, scrypt, or Argon2.",
                            severity=Severity.HIGH,
                            rule_id="JV-012",
                            cwe="CWE-328",
                        ))
                        break
    return findings


def _check_ssrf(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-918: Server-Side Request Forgery detection."""
    findings: list[Finding] = []
    for method in methods:
        calls = _collect_method_invocations(
            _JAVA_PARSER.parse(method.body.encode("utf-8")).root_node,
            method.body.encode("utf-8"),
        )
        for call in calls:
            if call.callee == "openConnection" and _has_dynamic_input(call.arguments, method.params):
                findings.append(_make_finding(
                    line=call.line,
                    title=f"CWE-918: SSRF via openConnection() at line {call.line}",
                    description=f"`openConnection()` called with dynamic URL at L{call.line}: `{call.raw[:100]}`.",
                    suggestion="Validate URLs against an allowlist. Never pass user-supplied URLs directly to HTTP clients.",
                    severity=Severity.HIGH,
                    rule_id="JV-009",
                    cwe="CWE-918",
                ))

        # Check URL object creation
        creations = _collect_object_creations(
            _JAVA_PARSER.parse(method.body.encode("utf-8")).root_node,
            method.body.encode("utf-8"),
        )
        for class_name, args, line in creations:
            if class_name == "URL" and _has_dynamic_input(args, method.params):
                findings.append(_make_finding(
                    line=line,
                    title=f"CWE-918: SSRF via URL() at line {line}",
                    description=f"`new URL()` with dynamic input at L{line}.",
                    suggestion="Validate URLs against an allowlist before constructing URL objects.",
                    severity=Severity.HIGH,
                    rule_id="JV-009",
                    cwe="CWE-918",
                ))
    return findings


def _check_open_redirect(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-601: Open redirect detection."""
    findings: list[Finding] = []
    for method in methods:
        calls = _collect_method_invocations(
            _JAVA_PARSER.parse(method.body.encode("utf-8")).root_node,
            method.body.encode("utf-8"),
        )
        for call in calls:
            if call.callee != "sendRedirect":
                continue
            if not _has_dynamic_input(call.arguments, method.params):
                continue
            findings.append(_make_finding(
                line=call.line,
                title=f"CWE-601: Open redirect via sendRedirect() at line {call.line}",
                description=f"`sendRedirect()` with dynamic URL at L{call.line}: `{call.raw[:100]}`.",
                suggestion="Validate redirect URLs against a static allowlist.",
                severity=Severity.MEDIUM,
                rule_id="JV-010",
                cwe="CWE-601",
            ))
    return findings


def _check_xss(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-79: Cross-Site Scripting via response writer."""
    findings: list[Finding] = []
    for method in methods:
        calls = _collect_method_invocations(
            _JAVA_PARSER.parse(method.body.encode("utf-8")).root_node,
            method.body.encode("utf-8"),
        )
        for call in calls:
            if call.callee == "write" and _has_dynamic_input(call.arguments, method.params):
                # Only flag if receiver suggests HTTP response (not JSON/generic writer)
                rcvr_lower = call.receiver.lower()
                if rcvr_lower and rcvr_lower not in _XSS_RESPONSE_RECEIVERS:
                    continue
                findings.append(_make_finding(
                    line=call.line,
                    title=f"CWE-79: XSS via response write() at line {call.line}",
                    description=f"Response writer with dynamic content at L{call.line}: `{call.raw[:100]}`.",
                    suggestion="HTML-encode all user-supplied data before writing to the HTTP response.",
                    severity=Severity.HIGH,
                    rule_id="JV-006",
                    cwe="CWE-79",
                ))
    return findings


def _check_hardcoded_secrets(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-798: Hardcoded credentials detection."""
    findings: list[Finding] = []
    _SECRET_RE = re.compile(
        r'\b(?:password|passwd|pwd|apiKey|apikey|secret|secretKey|token)\b\s*=\s*"([^"]{3,})"',
        re.IGNORECASE,
    )
    for method in methods:
        for match in _SECRET_RE.finditer(method.body):
            if any(skip in match.group(1).lower() for skip in ("placeholder", "example", "your-", "xxx", "test")):
                continue
            line = method.start_line + method.body[:match.start()].count("\n")
            findings.append(_make_finding(
                line=line,
                title=f"CWE-798: Hardcoded credential at line {line}",
                description=f"Hardcoded secret value found at L{line}: `{match.group(1)[:30]}...`.",
                suggestion="Use environment variables, a secrets manager, or a configuration server.",
                severity=Severity.HIGH,
                rule_id="JV-008",
                cwe="CWE-798",
            ))
    return findings


def _check_path_traversal(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-22: Path traversal detection."""
    findings: list[Finding] = []
    for method in methods:
        # Check File* constructors
        creations = _collect_object_creations(
            _JAVA_PARSER.parse(method.body.encode("utf-8")).root_node,
            method.body.encode("utf-8"),
        )
        for class_name, args, line in creations:
            if class_name in _PATH_TRAVERSAL_CLASSES and _has_dynamic_input(args, method.params):
                findings.append(_make_finding(
                    line=line,
                    title=f"CWE-22: Path traversal via new {class_name}() at line {line}",
                    description=f"`new {class_name}()` with dynamic path at L{line}.",
                    suggestion="Validate and sanitize file paths. Use a restricted base directory.",
                    severity=Severity.HIGH,
                    rule_id="JV-008",
                    cwe="CWE-22",
                ))

        # Check Paths.get
        calls = _collect_method_invocations(
            _JAVA_PARSER.parse(method.body.encode("utf-8")).root_node,
            method.body.encode("utf-8"),
        )
        for call in calls:
            if call.callee == "get" and call.receiver == "Paths" and _has_dynamic_input(call.arguments, method.params):
                findings.append(_make_finding(
                    line=call.line,
                    title=f"CWE-22: Path traversal via Paths.get() at line {call.line}",
                    description=f"`Paths.get()` with dynamic path at L{call.line}: `{call.raw[:100]}`.",
                    suggestion="Validate and sanitize file paths. Normalize before use.",
                    severity=Severity.HIGH,
                    rule_id="JV-008",
                    cwe="CWE-22",
                ))
    return findings


def _check_auth_bypass(methods: list[_JavaMethod], source: bytes) -> list[Finding]:
    """CWE-862: Missing authorization on sensitive routes."""
    findings: list[Finding] = []
    for method in methods:
        # Check if it's a mutating route without auth
        has_mutating = any(
            ann.rsplit(".", 1)[-1].split("(", 1)[0] in _MUTATING_ANNOTATIONS
            for ann in method.annotations
        )
        if not has_mutating:
            # Also flag GET endpoints exposing actuator/sensitive paths without auth
            has_actuator = any(
                "/actuator/" in rp or "/env" in rp or "/heapdump" in rp
                for ann in method.annotations
                for rp in (re.findall(r'"([^"]*)"', ann) or [])
            )
            if not has_actuator:
                continue
        if method.has_auth:
            continue
        # Check for manual security checks in body
        if re.search(r'SecurityContextHolder|getAuthentication|isAuthenticated|hasRole|hasAuthority',
                     method.body):
            continue
        findings.append(_make_finding(
            line=method.start_line,
            title=f"CWE-862: Missing authorization on mutating route {method.name}() at line {method.start_line}",
            description=f"Mutating endpoint `{method.name}()` at L{method.start_line} has no auth annotation or manual security check.",
            suggestion="Add @PreAuthorize, @Secured, or manual auth check.",
            severity=Severity.HIGH,
            rule_id="JV-009",
            cwe="CWE-862",
        ))
    return findings


# ── Main analyzer ───────────────────────────────────────────────────────────

_ALL_CHECKERS: list[tuple[str, Any]] = [
    ("CWE-89 SQLi", _check_sqli),
    ("CWE-78 CMDi", _check_cmd_injection),
    ("CWE-328 WeakCrypto", _check_weak_crypto),
    ("CWE-918 SSRF", _check_ssrf),
    ("CWE-601 Redirect", _check_open_redirect),
    ("CWE-79 XSS", _check_xss),
    ("CWE-798 Secrets", _check_hardcoded_secrets),
    ("CWE-22 Traversal", _check_path_traversal),
    ("CWE-862 Auth", _check_auth_bypass),
]


def analyze_java_ast(
    code: str,
    filename: str = "",
) -> AnalysisResult:
    """Analyze Java source using tree-sitter AST.

    Returns an AnalysisResult with findings from all active checkers.
    """
    result = AnalysisResult(
        file_path=filename,
        language="java",
        lines_scanned=len(code.splitlines()),
    )

    source_bytes = code.encode("utf-8")
    try:
        tree = _JAVA_PARSER.parse(source_bytes)
    except Exception as exc:
        _log.debug("Tree-sitter parse failed for %r: %s", filename, exc)
        return result

    methods = _collect_methods(source_bytes, tree)
    if not methods:
        _log.debug("No methods extracted from %r", filename)

    for checker_label, checker_fn in _ALL_CHECKERS:
        try:
            result.findings.extend(checker_fn(methods, source_bytes))
        except Exception as exc:
            _log.debug("Java checker %s failed on %r: %s", checker_label, filename, exc, exc_info=True)

    return result
