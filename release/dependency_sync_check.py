#!/usr/bin/env python3
import argparse
import tomllib
import base64
import hashlib
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List, Set

import requests


SUFFIX_MAPPING = {
    "dlp": "devel:languages:python",
    "dlpb": "devel:languages:python:backports",
    "dlpn": "devel:languages:python:numeric",
    "Mf": "M17N:fonts",
    "dtc": "devel:tools:compiler",
}


@dataclass
class ObsPackage:
    name: str
    raw_name: str
    version: str
    spec_text: Optional[str]
    spec_hash: str
    origin: str
    suffix: Optional[str]
    target_list: str
    has_macro: bool = False


@dataclass
class ProductSubmodule:
    name: str
    path: str
    commit: str
    version: str = "[Not Found]"


@dataclass
class CheckResult:
    package: str
    status: str
    action: str
    details: Dict[str, str] = field(default_factory=dict)


def normalize_python_package_name(name: str) -> Set[str]:
    """
    Generates naming variants used across uv.lock, OBS RPM packages and Gitea repos.

    Examples:
      python-click -> click
      python-python-dotenv -> python-dotenv
      typing_extensions -> typing-extensions
    """
    candidates = {name, name.replace("_", "-"), name.replace("-", "_")}

    for prefix in ("python-", "python3-", "python311-", "python312-", "python313-"):
        if name.startswith(prefix):
            stripped = name[len(prefix):]
            candidates.add(stripped)
            candidates.add(stripped.replace("_", "-"))
            candidates.add(stripped.replace("-", "_"))

    # Re-add RPM-style names for uv.lock names.
    base_candidates = list(candidates)
    for candidate in base_candidates:
        if not candidate.startswith("python-"):
            candidates.add(f"python-{candidate}")

    return candidates


def canonical_key(name: str) -> str:
    """
    Canonical comparison key.

    uv.lock uses Python distribution names, while OBS/Gitea often use RPM names.
    We strip Python RPM prefixes and normalize common separators so that, for example:
      python-jaraco.context -> jaraco-context
      jaraco_context        -> jaraco-context
      python-python-dotenv -> python-dotenv
    """
    normalized = name.strip().replace("_", "-").replace(".", "-")

    for prefix in ("python-", "python3-", "python311-", "python312-", "python313-"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break

    return normalized.lower()


def extract_spec_version(spec_text: Optional[str]) -> Optional[str]:
    if not spec_text:
        return None

    version_match = re.search(
        r"(?i)^Version:\s*([^\s#]+)",
        spec_text,
        re.MULTILINE,
    )

    return version_match.group(1) if version_match else None


def calculate_hash(text: Optional[str]) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


def _dependency_name(dep) -> Optional[str]:
    """Return the dependency package name from uv.lock dependency entries."""
    if isinstance(dep, dict):
        return dep.get("name")

    if isinstance(dep, str):
        # Very defensive fallback for older/variant lock shapes.
        return re.split(r"[<>=!~;\s\[]", dep, maxsplit=1)[0] or None

    return None


def _package_dependency_names(pkg: dict) -> Set[str]:
    """Return normal runtime dependencies for a uv.lock package entry.

    Intentionally ignores optional dependencies and dependency groups, because the
    checker is meant to validate the default dependency group only.
    """
    deps: Set[str] = set()

    for dep in pkg.get("dependencies", []) or []:
        name = _dependency_name(dep)
        if name:
            deps.add(name)

    return deps


def _is_workspace_root_package(pkg: dict) -> bool:
    source = pkg.get("source") or {}

    if source.get("editable") == ".":
        return True

    if source.get("virtual") == ".":
        return True

    # Some uv.lock variants mark the project package as virtual without a path.
    if source.get("virtual") is True:
        return True

    return False


def extract_uv_lock_default_dependency_versions(lock_text: Optional[str]) -> Dict[str, str]:
    """Extract the transitive closure of the default dependency group from uv.lock.

    This does NOT return every [[package]] entry. It starts from the local/root
    package entry, follows only its normal `dependencies`, and recursively follows
    normal dependencies of those packages. It deliberately excludes dev/test/docs
    groups and optional dependencies.
    """
    if not lock_text:
        return {}

    data = tomllib.loads(lock_text)
    packages = data.get("package", []) or []

    by_name = {pkg.get("name"): pkg for pkg in packages if pkg.get("name")}
    roots = [pkg for pkg in packages if _is_workspace_root_package(pkg)]

    if not roots:
        sys.stderr.write(
            "[uv.lock] WARNING: could not identify a local/root package in uv.lock; "
            "falling back to all locked packages.\n"
        )
        return {
            pkg["name"]: str(pkg.get("version", "[No Version]"))
            for pkg in packages
            if pkg.get("name")
        }

    wanted: Set[str] = set()
    queue: List[str] = []

    for root in roots:
        for dep_name in _package_dependency_names(root):
            if dep_name not in wanted:
                wanted.add(dep_name)
                queue.append(dep_name)

    while queue:
        name = queue.pop(0)
        pkg = by_name.get(name)
        if not pkg:
            continue

        for dep_name in _package_dependency_names(pkg):
            if dep_name not in wanted:
                wanted.add(dep_name)
                queue.append(dep_name)

    versions: Dict[str, str] = {}
    for name in sorted(wanted):
        pkg = by_name.get(name)
        if pkg and pkg.get("version") is not None:
            versions[name] = str(pkg["version"])
        else:
            versions[name] = "[Missing from lock package list]"

    return versions


def load_uv_lock_versions(uv_lock_path: Optional[str]) -> Dict[str, str]:
    if not uv_lock_path:
        return {}

    try:
        with open(uv_lock_path, "rb") as f:
            lock_text = f.read().decode("utf-8")

        versions = extract_uv_lock_default_dependency_versions(lock_text)

        sys.stderr.write(
            f"[uv.lock] Loaded {len(versions)} default dependency packages from {uv_lock_path}\n"
        )
        return versions

    except FileNotFoundError:
        sys.stderr.write(f"[uv.lock] File not found: {uv_lock_path}\n")
    except Exception as e:
        sys.stderr.write(f"[uv.lock] Error reading {uv_lock_path}: {e}\n")

    return {}


def run_git_command(repo_path: str, args: List[str]) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", repo_path] + args,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout

    except Exception as e:
        sys.stderr.write(f"[product-repo] Git command failed: {e}\n")
        return ""


def load_product_submodules(product_repo_path: Optional[str]) -> Dict[str, ProductSubmodule]:
    """
    Reads submodule commits from the product repository tree.

    This requires only the product repository checkout.
    It does not require submodules to be initialized for commit detection.

    To read local .spec versions, however, submodules should be initialized:
      git submodule update --init --recursive
    """
    if not product_repo_path:
        return {}

    output = run_git_command(product_repo_path, ["ls-tree", "-r", "HEAD"])
    submodules: Dict[str, ProductSubmodule] = {}

    for line in output.splitlines():
        line = line.strip()

        # Example:
        # 160000 commit ed9b4eff... python-fastmcp
        match = re.match(
            r"^160000\s+commit\s+([0-9a-f]{40}|[0-9a-f]{64})\s+(.+)$",
            line,
        )

        if not match:
            continue

        commit = match.group(1)
        path = match.group(2)
        basename = os.path.basename(path.rstrip("/"))

        submodule = ProductSubmodule(
            name=basename,
            path=path,
            commit=commit,
        )

        submodules[canonical_key(basename)] = submodule

    sys.stderr.write(
        f"[product-repo] Loaded {len(submodules)} submodule entries from git tree\n"
    )

    return submodules


def read_local_submodule_spec_version(
    product_repo_path: Optional[str],
    submodule: ProductSubmodule,
) -> str:
    if not product_repo_path:
        return "[Not Found]"

    submodule_dir = os.path.join(product_repo_path, submodule.path)

    if not os.path.isdir(submodule_dir):
        return "[Not Found]"

    try:
        spec_file = next(
            (f for f in os.listdir(submodule_dir) if f.endswith(".spec")),
            None,
        )

        if not spec_file:
            return "[Not Found]"

        with open(
            os.path.join(submodule_dir, spec_file),
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as f:
            return extract_spec_version(f.read()) or "[Version tag not found]"

    except Exception:
        return "[Not Found]"


def verify_product_submodules_initialized(
    product_repo_path: Optional[str],
    product_submodules: Dict[str, ProductSubmodule],
) -> None:
    if not product_repo_path or not product_submodules:
        return

    uninitialized: List[str] = []

    unique_submodules = {
        submodule.path: submodule
        for submodule in product_submodules.values()
    }

    for submodule in unique_submodules.values():
        submodule_dir = os.path.join(product_repo_path, submodule.path)

        if not os.path.isdir(submodule_dir):
            uninitialized.append(submodule.path)
            continue

        try:
            entries = os.listdir(submodule_dir)
        except Exception:
            uninitialized.append(submodule.path)
            continue

        has_spec = any(f.endswith(".spec") for f in entries)
        has_dockerfile = any(f == "Dockerfile" for f in entries)

        if not entries or not (has_spec or has_dockerfile):
            uninitialized.append(submodule.path)

    if uninitialized:
        raise RuntimeError(
            "Some product submodules exist in the product repository but are not initialized "
            "or do not contain readable .spec files or Dockerfiles.\n\n"
            "Uninitialized/unreadable submodules:\n"
            + "\n".join(f"  - {m}" for m in sorted(uninitialized))
            + "\n\nRun from the product repository:\n"
            "    git submodule update --init --recursive"
        )


def attach_product_submodule_versions(
    product_repo_path: Optional[str],
    product_submodules: Dict[str, ProductSubmodule],
) -> None:
    if not product_repo_path or not product_submodules:
        return

    found = 0

    for submodule in product_submodules.values():
        submodule.version = read_local_submodule_spec_version(product_repo_path, submodule)
        if submodule.version != "[Not Found]":
            found += 1

    sys.stderr.write(
        f"[product-repo] Read local .spec versions from {found}/{len(product_submodules)} submodules\n"
    )


def parse_package_metadata(raw_pkg_name: str, project_name: str) -> Tuple[str, str, str, Optional[str]]:
    """
    Cleans an OBS package name, strips target suffixes/flags, and determines origin.
    """
    pkg_clean = raw_pkg_name.strip()
    has_primary = pkg_clean.endswith(":primary")
    base_str = pkg_clean[:-8] if has_primary else pkg_clean

    origin_repo = f"New Package from {project_name} (No suffix origin)"
    target_list = "standard"
    clean_name = base_str
    suffix_used = None

    if base_str.endswith(".new"):
        target_list = "updates"
        name_without_new = base_str[:-4]
        origin_repo = "Unknown Update"

        suffix_match = re.search(r"\.(dlp|dlpb|dlpn|Mf|dtc)$", name_without_new)
        if suffix_match:
            suffix_used = suffix_match.group(1)
            clean_name = name_without_new[:suffix_match.start()]
            origin_repo = f"Update for {SUFFIX_MAPPING[suffix_used]}"
        else:
            clean_name = name_without_new

    else:
        suffix_match = re.search(r"\.(dlp|dlpb|dlpn|Mf|dtc)$", base_str)
        if suffix_match:
            suffix_used = suffix_match.group(1)
            clean_name = base_str[:suffix_match.start()]
            target_list = suffix_used
            origin_repo = f"From {SUFFIX_MAPPING[suffix_used]}"

    return clean_name, target_list, origin_repo, suffix_used


def fetch_obs_spec(base_url: str, api_pkg_name: str) -> Tuple[Optional[str], str]:
    pkg_url = f"{base_url}/{api_pkg_name}"

    try:
        response = requests.get(pkg_url, timeout=10)
        if response.status_code != 200:
            return None, "[Error fetching package directory]"

        root = ET.fromstring(response.text)
        files = [entry.get("name") for entry in root.findall("entry") if entry.get("name")]
        spec_file = next((f for f in files if f.endswith(".spec")), None)

        if not spec_file:
            return None, "[No .spec file found]"

        spec_response = requests.get(f"{pkg_url}/{spec_file}", timeout=10)
        if spec_response.status_code == 200:
            spec_text = spec_response.text
            return spec_text, extract_spec_version(spec_text) or "[Version tag not found]"

    except Exception:
        pass

    return None, "[Error fetching spec file]"


def print_progress(idx: int, total_count: int, last_report_time: float, report_interval: float = 5.0) -> float:
    current_time = time.time()

    if current_time - last_report_time >= report_interval:
        percentage = (idx / total_count) * 100 if total_count else 100
        sys.stderr.write(
            f"[Progress] Processed {idx}/{total_count} packages ({percentage:.1f}%)\n"
        )
        sys.stderr.flush()
        return current_time

    return last_report_time


def load_obs_project_packages(
    project_name: str,
    build_service: str,
) -> Dict[str, ObsPackage]:
    base_url = f"https://{build_service}/public/source/{project_name}"

    sys.stderr.write(f"Connecting to {build_service} to fetch OBS project package list...\n")

    response = requests.get(base_url, timeout=10)
    response.raise_for_status()

    root = ET.fromstring(response.text)
    all_pkgs = [entry.get("name") for entry in root.findall("entry") if entry.get("name")]

    test_pattern = re.compile(r"[-:]test(-py3\d+)?$")
    packages = [pkg for pkg in all_pkgs if not test_pattern.search(pkg)]

    sys.stderr.write(f"[OBS] Total packages to process: {len(packages)}\n")

    obs_packages: Dict[str, ObsPackage] = {}
    last_report_time = time.time()

    for idx, pkg in enumerate(packages, start=1):
        last_report_time = print_progress(idx, len(packages), last_report_time)

        api_pkg_name = pkg[:-8] if pkg.endswith(":primary") else pkg
        spec_text, obs_version = fetch_obs_spec(base_url, api_pkg_name)
        spec_hash = calculate_hash(spec_text)

        clean_name, target_list, origin_repo, suffix_used = parse_package_metadata(pkg, project_name)

        obs_pkg = ObsPackage(
            name=clean_name,
            raw_name=pkg,
            version=obs_version,
            spec_text=spec_text,
            spec_hash=spec_hash,
            origin=origin_repo,
            suffix=suffix_used,
            target_list=target_list,
            has_macro=("%" in obs_version or "[" in obs_version),
        )

        # OBS can contain duplicate logical names from different source package entries.
        # Keep the first one, but print a warning because this should be understood explicitly.
        key = canonical_key(clean_name)
        if key in obs_packages:
            sys.stderr.write(
                f"[OBS] WARNING: duplicate logical package key '{key}' from "
                f"{obs_packages[key].raw_name} and {pkg}; keeping first\n"
            )
            continue

        obs_packages[key] = obs_pkg

    sys.stderr.write(f"[Progress] Completed OBS package loading ({len(packages)}/{len(packages)})\n\n")
    return obs_packages


def get_gitea_spec_content_and_version(
    gitea_url: str,
    repo_name: str,
    ref: str,
    headers: Dict[str, str],
) -> Tuple[Optional[str], Optional[str]]:
    url = f"{gitea_url}/api/v1/repos/pool/{repo_name}/contents/{repo_name}.spec"

    try:
        response = requests.get(
            url,
            params={"ref": ref},
            headers=headers,
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json()
            spec_text = (
                base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
                if isinstance(data, dict) and "content" in data
                else response.text
            )
            return spec_text, extract_spec_version(spec_text)

    except Exception:
        pass

    return None, None


def fetch_origin_devel_version(
    build_service: str,
    obs_pkg: ObsPackage,
) -> str:
    if obs_pkg.suffix not in SUFFIX_MAPPING:
        return "[Not Applicable]"

    origin_project = SUFFIX_MAPPING[obs_pkg.suffix]
    origin_base_url = f"https://{build_service}/public/source/{origin_project}"
    _, origin_ver = fetch_obs_spec(origin_base_url, obs_pkg.name)

    return origin_ver if origin_ver else "[Not Found]"


def version_status(left: str, right: str) -> str:
    """
    Conservative version comparison.

    Returns:
      same
      different
      unknown

    We intentionally do not try to order RPM/Python versions here because
    packaging.version may not handle every RPM-ish version string.
    """
    if not left or not right:
        return "unknown"
    if left.startswith("[") or right.startswith("["):
        return "unknown"
    if "%" in left or "%" in right:
        return "unknown"
    return "same" if left == right else "different"


def build_uv_index(uv_lock_versions: Dict[str, str]) -> Dict[str, Tuple[str, str]]:
    """
    canonical_key -> (original uv name, version)
    """
    return {
        canonical_key(name): (name, version)
        for name, version in uv_lock_versions.items()
    }


def compare_uv_lock_to_obs(
    uv_index: Dict[str, Tuple[str, str]],
    obs_packages: Dict[str, ObsPackage],
    build_service: str,
    include_devel_lookup: bool,
) -> List[CheckResult]:
    results: List[CheckResult] = []

    for key, (uv_name, uv_version) in sorted(uv_index.items()):
        obs_pkg = obs_packages.get(key)

        if not obs_pkg:
            results.append(
                CheckResult(
                    package=uv_name,
                    status="OBS_MISSING",
                    action="Add/copy this package into the OBS staging project",
                    details={
                        "uv.lock": uv_version,
                        "OBS": "[Missing]",
                    },
                )
            )
            continue

        status = version_status(uv_version, obs_pkg.version)

        if status == "same":
            results.append(
                CheckResult(
                    package=obs_pkg.name,
                    status="OK",
                    action="-",
                    details={
                        "uv.lock": uv_version,
                        "OBS": obs_pkg.version,
                    },
                )
            )

        elif status == "different":
            details = {
                "uv.lock": uv_version,
                "OBS": obs_pkg.version,
                "Origin": obs_pkg.origin,
            }

            if include_devel_lookup:
                details["devel"] = fetch_origin_devel_version(build_service, obs_pkg)

            results.append(
                CheckResult(
                    package=obs_pkg.name,
                    status="UV_OBS_VERSION_MISMATCH",
                    action="Decide direction: update uv.lock if OBS/devel is desired, or update OBS staging if uv.lock is desired",
                    details=details,
                )
            )

        else:
            results.append(
                CheckResult(
                    package=obs_pkg.name,
                    status="UNKNOWN_VERSION_COMPARISON",
                    action="Manual check required; version contains macros or could not be read",
                    details={
                        "uv.lock": uv_version,
                        "OBS": obs_pkg.version,
                        "Origin": obs_pkg.origin,
                    },
                )
            )

    return results


def compare_obs_to_product(
    obs_packages: Dict[str, ObsPackage],
    product_submodules: Dict[str, ProductSubmodule],
) -> List[CheckResult]:
    results: List[CheckResult] = []

    for key, obs_pkg in sorted(obs_packages.items(), key=lambda item: item[1].name.lower()):
        product = product_submodules.get(key)

        if not product:
            results.append(
                CheckResult(
                    package=obs_pkg.name,
                    status="PRODUCT_SUBMODULE_MISSING",
                    action="Add product submodule if this OBS package is required by the product build closure",
                    details={
                        "OBS": obs_pkg.version,
                        "Product": "[Missing]",
                        "Origin": obs_pkg.origin,
                    },
                )
            )
            continue

        status = version_status(obs_pkg.version, product.version)

        if status == "same":
            results.append(
                CheckResult(
                    package=obs_pkg.name,
                    status="OK",
                    action="-",
                    details={
                        "OBS": obs_pkg.version,
                        "Product": product.version,
                        "Commit": product.commit[:12],
                    },
                )
            )

        elif status == "different":
            results.append(
                CheckResult(
                    package=obs_pkg.name,
                    status="OBS_PRODUCT_VERSION_MISMATCH",
                    action="Update product submodule pointer to the commit matching OBS staging",
                    details={
                        "OBS": obs_pkg.version,
                        "Product": product.version,
                        "Commit": product.commit[:12],
                    },
                )
            )

        else:
            results.append(
                CheckResult(
                    package=obs_pkg.name,
                    status="UNKNOWN_PRODUCT_VERSION",
                    action="Initialize/update submodule and ensure its .spec file is readable",
                    details={
                        "OBS": obs_pkg.version,
                        "Product": product.version,
                        "Commit": product.commit[:12],
                    },
                )
            )

    return results


def compare_product_to_obs(
    product_submodules: Dict[str, ProductSubmodule],
    obs_packages: Dict[str, ObsPackage],
) -> List[CheckResult]:
    results: List[CheckResult] = []

    for key, product in sorted(product_submodules.items(), key=lambda item: item[1].name.lower()):
        obs_pkg = obs_packages.get(key)

        if obs_pkg:
            continue

        results.append(
            CheckResult(
                package=product.name,
                status="PRODUCT_ORPHAN_SUBMODULE",
                action="Consider removing this product submodule or adding the corresponding package to OBS staging",
                details={
                    "Product": product.version,
                    "Commit": product.commit[:12],
                    "OBS": "[Missing]",
                    "Path": product.path,
                },
            )
        )

    return results


def print_results(title: str, results: List[CheckResult], show_ok: bool = False) -> int:
    print(f"\n### {title} ###")

    visible_results = results if show_ok else [r for r in results if r.status != "OK"]

    if not visible_results:
        print("  [None]")
        return 0

    failures = 0

    for r in visible_results:
        if r.status != "OK":
            failures += 1

        detail_str = " | ".join(
            f"{key}: {value}"
            for key, value in r.details.items()
        )

        print(
            f"  {r.package:<40}"
            f" | Status: {r.status:<30}"
            f" | {detail_str}"
            f" | Action: {r.action}"
        )

    return failures


def print_summary(
    uv_obs_results: List[CheckResult],
    obs_product_results: List[CheckResult],
    product_orphan_results: List[CheckResult],
    show_ok: bool,
) -> int:
    print("=" * 80)
    print(" SYNC EVALUATION: uv.lock -> OBS staging (+ build deps) -> product submodules")
    print("=" * 80)

    uv_obs_failures = print_results(
        "uv.lock dependencies vs OBS staging",
        uv_obs_results,
        show_ok=show_ok,
    )

    obs_product_failures = print_results(
        "OBS staging packages vs product submodules",
        obs_product_results,
        show_ok=show_ok,
    )

    orphan_failures = print_results(
        "Product submodules not present in OBS staging",
        product_orphan_results,
        show_ok=show_ok,
    )

    print("\n### Health Summary ###")
    print(f"  uv.lock vs OBS issues:          {uv_obs_failures}")
    print(f"  OBS vs product issues:          {obs_product_failures}")
    print(f"  product orphan submodules:      {orphan_failures}")

    total = uv_obs_failures + obs_product_failures + orphan_failures

    if total == 0:
        print("  Overall: PASSED")
    else:
        print("  Overall: FAILED")

    return total


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Check synchronization across uv.lock, OBS staging project and "
            "Gitea product submodules."
        )
    )

    parser.add_argument("project", help="The OBS staging project name")
    parser.add_argument(
        "-s",
        "--service",
        default="api.opensuse.org",
        help="The OBS instance domain",
    )
    parser.add_argument(
        "-g",
        "--gitea",
        default="src.opensuse.org",
        help="The Gitea host configuration domain",
    )

    parser.add_argument(
        "--uv-lock",
        default=None,
        help="Path to uv.lock. If provided, only the default dependency closure is compared with OBS.",
    )
    parser.add_argument(
        "--product-repo",
        default=None,
        help=(
            "Path to the cloned product Git repository. "
            "For product version checks, run git submodule update --init --recursive first."
        ),
    )
    parser.add_argument(
        "--show-ok",
        action="store_true",
        help="Show OK rows in addition to issues.",
    )
    parser.add_argument(
        "--skip-devel-lookup",
        action="store_true",
        help="Do not query origin devel projects when uv.lock and OBS mismatch.",
    )

    args = parser.parse_args()

    build_service = args.service
    
    try:
        uv_lock_versions = load_uv_lock_versions(args.uv_lock)
        uv_index = build_uv_index(uv_lock_versions)

        obs_packages = load_obs_project_packages(args.project, build_service)

        product_submodules = load_product_submodules(args.product_repo)
        verify_product_submodules_initialized(args.product_repo, product_submodules)
        attach_product_submodule_versions(args.product_repo, product_submodules)

        uv_obs_results = compare_uv_lock_to_obs(
            uv_index=uv_index,
            obs_packages=obs_packages,
            build_service=build_service,
            include_devel_lookup=not args.skip_devel_lookup,
        )

        obs_product_results = compare_obs_to_product(
            obs_packages=obs_packages,
            product_submodules=product_submodules,
        )

        product_orphan_results = compare_product_to_obs(
            product_submodules=product_submodules,
            obs_packages=obs_packages,
        )

        issues = print_summary(
            uv_obs_results=uv_obs_results,
            obs_product_results=obs_product_results,
            product_orphan_results=product_orphan_results,
            show_ok=args.show_ok,
        )

        if issues > 0:
            sys.stderr.write(f"\n[HEALTH CHECK] FAILED: Found {issues} sync issues.\n")
            return 1

        sys.stderr.write("\n[HEALTH CHECK] PASSED: Sync chain is healthy.\n")
        return 0

    except Exception as e:
        sys.stderr.write(f"An error occurred: {e}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
