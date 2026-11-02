import ast
from pathlib import Path

import pytest


SOURCE_ROOT = Path(__file__).resolve().parents[2] / "src" / "mcp_server_uyuni"
LAYERS = ("api", "workflows", "tools", "common")
FORBIDDEN = {
    "api": {"workflows", "tools"},
    "workflows": {"tools"},
    "common": {"api", "workflows", "tools"},
}


def violations(source_root):
    found = []
    for layer in LAYERS:
        for path in sorted((source_root / layer).rglob("*.py")):
            package = ["mcp_server_uyuni", *path.relative_to(source_root).parent.parts]
            tree = ast.parse(path.read_text(), filename=str(path))
            for node in ast.walk(tree):
                targets = []
                if isinstance(node, ast.Import):
                    targets = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        prefix = package[:len(package) - node.level + 1]
                        module_parts = node.module.split(".") if node.module else []
                        target_parts = [*prefix, *module_parts]
                        target = ".".join(target_parts)
                        targets = [target]
                        if node.module is None:
                            targets += [".".join([*target_parts, alias.name]) for alias in node.names]
                    else:
                        targets = [node.module or ""]
                for target in targets:
                    parts = target.split(".")
                    if len(parts) >= 2 and parts[0] == "mcp_server_uyuni":
                        if parts[1] in FORBIDDEN.get(layer, set()):
                            found.append(f"{path}:{node.lineno}: {layer} -> {parts[1]}")
    return found


def test_production_import_boundaries():
    assert violations(SOURCE_ROOT) == []


@pytest.mark.parametrize(
    "source_layer,target_layer",
    [("api", "workflows"), ("api", "tools"), ("workflows", "tools"),
     ("common", "api"), ("common", "workflows"), ("common", "tools")],
)
def test_boundary_checker_rejects_reverse_imports(tmp_path, source_layer, target_layer):
    source = tmp_path / source_layer
    source.mkdir()
    (source / "bad.py").write_text(f"from mcp_server_uyuni.{target_layer} import example\n")
    assert len(violations(tmp_path)) == 1


def test_boundary_checker_rejects_relative_import(tmp_path):
    source = tmp_path / "api"
    source.mkdir()
    (source / "bad.py").write_text("from .. import tools\n")
    assert len(violations(tmp_path)) == 1
