import argparse
from pathlib import Path


def validate_version(value: str) -> str:
    """Validates that a string adheres to the major.minor.patch format."""
    parts = value.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise argparse.ArgumentTypeError(
            f"Invalid version format '{value}'. Expected <major>.<minor>.<patch> (e.g., 1.2.0)"
        )
    return value


def update_pyproject_version(pyproject_path: Path, new_version: str) -> str:
    """Updates the version under [project] in pyproject.toml and returns project name."""
    if not pyproject_path.is_file():
        raise FileNotFoundError(f"pyproject.toml not found at {pyproject_path}")

    lines = pyproject_path.read_text(encoding="utf-8").splitlines(keepends=True)
    in_project_section = False
    updated = False
    project_name = None
    new_lines = []

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("[") and stripped.endswith("]"):
            in_project_section = stripped == "[project]"
            new_lines.append(line)
            continue

        if in_project_section:
            if stripped.startswith("name"):
                key, _, val = stripped.partition("=")
                if key.strip() == "name":
                    project_name = val.strip().strip('"').strip("'")
            elif not updated and stripped.startswith("version"):
                key, _, _ = stripped.partition("=")
                if key.strip() == "version":
                    new_lines.append(f'version = "{new_version}"\n')
                    updated = True
                    continue

        new_lines.append(line)

    if not updated:
        raise ValueError(f"Could not find 'version' under '[project]' in {pyproject_path}")
    if not project_name:
        raise ValueError(f"Could not find 'name' under '[project]' in {pyproject_path}")

    pyproject_path.write_text("".join(new_lines), encoding="utf-8")
    return project_name


def update_uv_lock_version(uv_lock_path: Path, project_name: str, new_version: str) -> None:
    """Updates the version of the main project package in uv.lock without regex."""
    if not uv_lock_path.is_file():
        raise FileNotFoundError(f"uv.lock not found at {uv_lock_path}")

    lines = uv_lock_path.read_text(encoding="utf-8").splitlines(keepends=True)
    new_lines = []
    block_lines = []
    in_package = False
    updated = False

    def process_block(block: list[str]) -> list[str]:
        nonlocal updated
        is_target = False
        for line in block:
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]") and stripped != "[[package]]":
                break
            if stripped.startswith("name"):
                k, _, v = stripped.partition("=")
                if k.strip() == "name" and v.strip().strip('"').strip("'") == project_name:
                    is_target = True
                    break

        if not is_target:
            return block

        result = []
        ver_updated = False
        in_main_table = True
        for line in block:
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                in_main_table = stripped == "[[package]]"

            if in_main_table and not ver_updated and stripped.startswith("version"):
                k, _, _ = stripped.partition("=")
                if k.strip() == "version":
                    result.append(f'version = "{new_version}"\n')
                    ver_updated = True
                    updated = True
                    continue
            result.append(line)

        return result

    for line in lines:
        stripped = line.strip()
        if stripped == "[[package]]":
            if block_lines:
                new_lines.extend(process_block(block_lines))
                block_lines = []
            in_package = True

        if in_package:
            block_lines.append(line)
        else:
            new_lines.append(line)

    if block_lines:
        new_lines.extend(process_block(block_lines))

    if not updated:
        raise ValueError(f"Could not find package '{project_name}' in {uv_lock_path}")

    uv_lock_path.write_text("".join(new_lines), encoding="utf-8")


def update_spec_version(spec_path: Path, new_version: str) -> None:
    """Updates the %global p_version definition in the RPM spec file without regex."""
    if not spec_path.is_file():
        raise FileNotFoundError(f"Spec file not found at {spec_path}")

    lines = spec_path.read_text(encoding="utf-8").splitlines(keepends=True)
    new_lines = []
    updated = False

    for line in lines:
        tokens = line.split()
        if not updated and len(tokens) >= 2 and tokens[0] == "%global" and tokens[1] == "p_version":
            # Preserve leading indentation if any existed
            prefix = line[:line.find("%global")]
            new_lines.append(f"{prefix}%global p_version {new_version}\n")
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        raise ValueError(f"Could not find '%global p_version' in {spec_path}")

    spec_path.write_text("".join(new_lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bump the project version in pyproject.toml and uv.lock."
    )
    parser.add_argument(
        "new_version",
        type=validate_version,
        help="New version string in major.minor.patch format (e.g., 1.2.3)",
    )

    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    pyproject_path = project_root / "pyproject.toml"
    uv_lock_path = project_root / "uv.lock"
    spec_path = project_root / "release" / "packages" / "mlm" / "python-mcp-server-mlm" / "python-mcp-server-mlm.spec"

    project_name = update_pyproject_version(pyproject_path, args.new_version)
    print(f"Updated {pyproject_path.name} to version {args.new_version}")

    update_uv_lock_version(uv_lock_path, project_name, args.new_version)
    print(f"Updated {uv_lock_path.name} for package '{project_name}' to version {args.new_version}")

    update_spec_version(spec_path, args.new_version)
    print(f"Updated {spec_path.name} to version {args.new_version}")

if __name__ == "__main__":
    main()
