# Rule Database Overview

Ansede rules are distributed across curated native detectors and YAML community/runtime rules.

## Severity calibration

- **CRITICAL**: direct code execution or full auth bypass paths
- **HIGH**: horizontal/vertical privilege escalation paths (e.g., IDOR/BOLA)
- **MEDIUM**: cryptographic weaknesses, traversal, insecure defaults
- **LOW**: hardening and information-disclosure hygiene issues

## Export full rule catalog

```bash
ansede-static --export-rules json --output rules.json
ansede-static --export-rules yaml --output rules.yaml
```

## Explain a CWE

```bash
ansede-static --explain-cwe CWE-639
```
