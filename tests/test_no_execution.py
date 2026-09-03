from __future__ import annotations

import ast
import unittest
from pathlib import Path


RUNTIME = Path(__file__).resolve().parents[1] / "malware_archive"
VIEWER = Path(__file__).resolve().parents[1] / "artifact_viewer"
FORBIDDEN_MODULES = {"importlib", "pip", "runpy", "subprocess", "tarfile", "venv", "zipfile"}
FORBIDDEN_BUILTINS = {
    "__import__",
    "compile",
    "eval",
    "exec",
}
FORBIDDEN_CALLS = {
    "extract",
    "extractall",
    "popen",
    "system",
    "unpack_archive",
}


class NoPackageExecutionTests(unittest.TestCase):
    def test_runtime_has_no_install_extract_or_execution_primitives(self) -> None:
        violations: list[str] = []
        for path in sorted(RUNTIME.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split(".", 1)[0] in FORBIDDEN_MODULES:
                            violations.append(f"{path.name}:{node.lineno}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    module = (node.module or "").split(".", 1)[0]
                    if module in FORBIDDEN_MODULES:
                        violations.append(f"{path.name}:{node.lineno}: from {node.module} import ...")
                elif isinstance(node, ast.Call):
                    function = node.func
                    name = function.id if isinstance(function, ast.Name) else ""
                    attribute = function.attr if isinstance(function, ast.Attribute) else ""
                    if name in FORBIDDEN_BUILTINS or (name or attribute).lower() in FORBIDDEN_CALLS:
                        name = name or attribute
                        violations.append(f"{path.name}:{node.lineno}: call {name}(...)")
        self.assertEqual(violations, [], "forbidden runtime primitives detected:\n" + "\n".join(violations))

    def test_viewer_has_no_process_or_execution_primitives(self) -> None:
        forbidden_modules = {"importlib", "pip", "runpy", "subprocess", "venv"}
        forbidden_calls = FORBIDDEN_CALLS | FORBIDDEN_BUILTINS
        violations: list[str] = []
        for path in sorted(VIEWER.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                    for name in names:
                        if name.split(".", 1)[0] in forbidden_modules:
                            violations.append(f"{path.name}:{node.lineno}: import {name}")
                elif isinstance(node, ast.Call):
                    function = node.func
                    name = function.id if isinstance(function, ast.Name) else ""
                    attribute = function.attr if isinstance(function, ast.Attribute) else ""
                    if (name or attribute).lower() in forbidden_calls:
                        violations.append(f"{path.name}:{node.lineno}: call {name or attribute}(...)")
        self.assertEqual(violations, [], "viewer execution primitives detected:\n" + "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
