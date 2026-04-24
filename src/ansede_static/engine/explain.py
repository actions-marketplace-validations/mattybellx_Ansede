"""
ansede_static.engine.explain
─────────────────────────────
Zero-dependency, offline Heuristic Auto-Remediation Engine.
Injects beautiful markdown explanations for standard CWEs, simulating the 
educational feedback of a local LLM but completely offline and instant.
"""

from typing import Dict

EXPLANATIONS: Dict[str, str] = {
    "CWE-89": """### SQL Injection (CWE-89)
**What it is:**
SQL Injection occurs when user input is concatenated directly into a database query string. This allows an attacker to manipulate the query's logic, potentially bypassing authentication, wiping the database, or extracting sensitive tables.

**Why the fix works:**
By using *parameterized queries* (e.g., `(?,)` in SQLite or `%s` in psycopg2), the database driver treats the user input strictly as compiled literal data, not as executable code. Even if an attacker enters `' OR 1=1 --`, it will just be treated as a weirdly named string.""",

    "CWE-78": """### OS Command Injection (CWE-78)
**What it is:**
Command Injection happens when an application passes unsafe user-supplied data to a system shell. This can lead to arbitrary command execution (e.g., `; rm -rf /` appended to an image name).

**Why the fix works:**
By turning `shell=True` to `shell=False` and passing arguments as a list (e.g., `['ls', '-l', user_dir]`), the operating system executes the binary directly without passing the string through a shell interpreter (`sh` or `cmd.exe`). This neutralizes shell metacharacters like `;`, `&&`, and `|`.""",

    "CWE-79": """### Cross-Site Scripting (CWE-79)
**What it is:**
XSS occurs when an application includes untrusted data in a web page without proper validation or escaping. If an attacker injects `<script>steal_cookies()</script>`, the victim's browser will execute it.

**Why the fix works:**
Using a templating engine with automatic Context-Aware Escaping (like Jinja2) or calling an explicit HTML escape function converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their safe HTML entities (e.g., `&lt;`).""",

    "CWE-918": """### Server-Side Request Forgery (CWE-918)
**What it is:**
SSRF occurs when a web application makes a network request to an arbitrary URL supplied by a user. Attackers can abuse this to probe internal networks, cloud metadata endpoints (like AWS `169.254.169.254`), or bypass firewalls.

**Why the fix works:**
Validating the requested URL against a rigorous *allowlist* of permitted hostnames before making the HTTP fetch guarantees the server will never route requests to internal or strictly private IP spaces.""",

    "CWE-502": """### Unsafe Deserialization (CWE-502)
**What it is:**
Deserialization of untrusted data (like `pickle.loads` or `yaml.load`) is highly dangerous because these formats can instantiate arbitrary Python objects. A crafted payload can trigger `__reduce__` methods to execute OS commands instantly upon loading.

**Why the fix works:**
Switching to a pure-data serialization format like JSON (`json.loads`) ensures that only primitive dictionaries and lists are created, effectively eliminating the risk of arbitrary code execution."""
}

def get_explanation(cwe_id: str) -> str:
    """Returns the markdown explanation for a given CWE, or a generic fallback."""
    if not cwe_id:
        return ""
    
    # Normalize
    cwe_id = cwe_id.upper()
    if cwe_id in EXPLANATIONS:
        return EXPLANATIONS[cwe_id]
        
    return f"### {cwe_id}\n\n**What it is:**\nThis vulnerability was detected based on data-flow and architectural heuristics. Consider reviewing the standard OWASP guidelines for {cwe_id}."
