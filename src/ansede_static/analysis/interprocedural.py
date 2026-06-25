from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class SymbolLocation:
    module: str
    file_path: str
    line: int
    symbol: str


@dataclass
class GlobalProjectIndex:
    symbols: dict[str, SymbolLocation] = field(default_factory=dict)
    imports: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def resolve(self, qualified_symbol: str) -> SymbolLocation | None:
        return self.symbols.get(qualified_symbol)


def _module_name_from_path(root: Path, file_path: Path) -> str:
    rel = file_path.resolve().relative_to(root.resolve())
    return ".".join(rel.with_suffix("").parts)


def build_project_index(root: Path) -> GlobalProjectIndex:
    """Build a project-wide symbol/import index for cross-file resolution."""
    index = GlobalProjectIndex()
    for path in sorted(root.rglob("*.py")):
        if any(part in {".git", "__pycache__", ".venv", "venv", "node_modules"} for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except SyntaxError:
            continue

        module = _module_name_from_path(root, path)
        imported: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qname = f"{module}.{node.name}"
                index.symbols[qname] = SymbolLocation(
                    module=module,
                    file_path=str(path),
                    line=getattr(node, "lineno", 1),
                    symbol=node.name,
                )
            elif isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                for alias in node.names:
                    imported.append(f"{base}.{alias.name}" if base else alias.name)

        index.imports[module] = tuple(sorted(set(name for name in imported if name)))

    return index
