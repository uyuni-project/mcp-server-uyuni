import argparse
import base64
import hashlib
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import requests


SUFFIX_MAPPING = {
    "dlp": "devel:languages:python",
    "dlpb": "devel:languages:python:backports",
    "dlpn": "devel:languages:python:numeric",
    "Mf": "M17N:fonts",
    "dtc": "devel:tools:compiler",
}


def extract_spec_version(spec_text):
    if not spec_text:
        return None
    version_match = re.search(r"(?i)^Version:\s*([^\s#]+)", spec_text, re.MULTILINE)
    return version_match.group(1) if version_match else None


def calculate_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""


def extract_uv_lock_versions(lock_text):
    versions = {}
    current_name = None

    if not lock_text:
        return versions

    for line in lock_text.splitlines():
        line = line.strip()

        if line == "[[package]]":
            current_name = None
            continue

        name_match = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if name_match:
            current_name = name_match.group(1)
            continue

        version_match = re.match(r'^version\s*=\s*"([^"]+)"', line)
        if version_match and current_name:
            versions[current_name] = version_match.group(1)

    return versions


def load_uv_lock_versions(uv_lock_path):
    if not uv_lock_path:
        return {}

    try:
        with open(uv_lock_path, "r", encoding="utf-8") as f:
            versions = extract_uv_lock_versions(f.read())
        sys.stderr.write(f"[uv.lock] Loaded {len(versions)} package versions from {uv_lock_path}\n")
        return versions
    except FileNotFoundError:
        sys.stderr.write(f"[uv.lock] File not found: {uv_lock_path}\n")
    except Exception as e:
        sys.stderr.write(f"[uv.lock] Error reading {uv_lock_path}: {e}\n")

    return {}


def normalize_python_package_name(name):
    candidates = {name}

    for prefix in ("python-", "python3-", "python311-", "python312-", "python313-"):
        if name.startswith(prefix):
            candidates.add(name[len(prefix):])

    candidates.add(f"python-{name}")
    candidates.add(name.replace("_", "-"))
    candidates.add(name.replace("-", "_"))

    return candidates


def run_git_command(repo_path, args):
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


def load_product_submodules(product_repo_path):
    if not product_repo_path:
        return {}

    output = run_git_command(product_repo_path, ["ls-tree", "-r", "HEAD"])
    submodules = {}

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

        submodules[path] = commit
        submodules[basename] = commit

    sys.stderr.write(f"[product-repo] Loaded {len(submodules)} submodule references from git tree\n")
    return submodules


def find_product_submodule_commit(pkg_name, product_submodules):
    for candidate in normalize_python_package_name(pkg_name):
        if candidate in product_submodules:
            return product_submodules[candidate]
    return None


def get_gitea_spec_content_and_version(gitea_url, repo_name, ref, headers):
    url = f"{gitea_url}/api/v1/repos/pool/{repo_name}/contents/{repo_name}.spec"

    try:
        response = requests.get(url, params={"ref": ref}, headers=headers, timeout=10)

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


def print_progress(idx, total_count, last_report_time, report_interval=5.0):
    current_time = time.time()

    if current_time - last_report_time >= report_interval:
        percentage = (idx / total_count) * 100
        sys.stderr.write(f"[Progress] Processed {idx}/{total_count} packages ({percentage:.1f}%)\n")
        sys.stderr.flush()
        return current_time

    return last_report_time


def parse_package_metadata(raw_pkg_name, project_name):
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


def fetch_obs_spec(base_url, api_pkg_name):
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
            return spec_response.text, extract_spec_version(spec_response.text) or "[Version tag not found]"

    except Exception:
        pass

    return None, "[Error fetching spec file]"


def attach_uv_lock_status(pkg_data, uv_lock_versions):
    if not uv_lock_versions:
        return

    uv_version = None

    for candidate in normalize_python_package_name(pkg_data["name"]):
        if candidate in uv_lock_versions:
            uv_version = uv_lock_versions[candidate]
            break

    pkg_data["uv_lock_version"] = uv_version if uv_version else "[Not Found]"
    pkg_data["uv_lock_mismatch"] = bool(uv_version and uv_version != pkg_data["version"])


def attach_product_submodule_status(gitea_url, headers, pkg_data, product_submodules):
    if not product_submodules:
        return

    commit = find_product_submodule_commit(pkg_data["name"], product_submodules)

    if not commit:
        pkg_data["product_submodule_commit"] = "[Not Found]"
        pkg_data["product_submodule_version"] = "[Not Found]"
        pkg_data["product_submodule_mismatch"] = True
        return

    pkg_data["product_submodule_commit"] = commit[:12]

    _, product_ver = get_gitea_spec_content_and_version(
        gitea_url,
        pkg_data["name"],
        commit,
        headers,
    )

    pkg_data["product_submodule_version"] = product_ver if product_ver else "[Not Found]"
    pkg_data["product_submodule_mismatch"] = product_ver != pkg_data["version"]


def evaluate_gitea_sync(gitea_url, headers, pkg_data, obs_hash):
    repo_url = f"{gitea_url}/api/v1/repos/pool/{pkg_data['name']}"

    try:
        response = requests.get(repo_url, headers=headers, timeout=5)
    except Exception:
        return "mismatch_or_missing"

    if response.status_code == 404:
        return "new_packages"

    if response.status_code == 200:
        f_text, f_ver = get_gitea_spec_content_and_version(gitea_url, pkg_data["name"], "factory", headers)
        m_text, m_ver = get_gitea_spec_content_and_version(gitea_url, pkg_data["name"], "mlm-mcp-main", headers)

        pkg_data["factory_version"] = f_ver if f_ver else "[Not Found/Empty]"

        f_hash = calculate_hash(f_text)
        m_hash = calculate_hash(m_text)

        if obs_hash and obs_hash == f_hash:
            return "factory_match"

        if obs_hash and obs_hash == m_hash:
            return "mlm_main_match"

        if not pkg_data["has_macro"] and pkg_data["version"] in (f_ver, m_ver):
            pkg_data["version"] += " [Content Drift]"
            return "mismatch_or_missing"

        if pkg_data["has_macro"]:
            pkg_data["version"] += " [Macro Diverged]"

    return "mismatch_or_missing"


def format_uv_lock_status(p):
    if "uv_lock_version" not in p:
        return ""

    if p.get("uv_lock_mismatch"):
        return f" | uv.lock: {p['uv_lock_version']:<10} [NEEDS UPDATE]"

    return f" | uv.lock: {p['uv_lock_version']:<10}"


def format_product_submodule_status(p):
    if "product_submodule_version" not in p:
        return ""

    if p.get("product_submodule_mismatch"):
        return (
            f" | Product: {p['product_submodule_version']:<10}"
            f" @ {p.get('product_submodule_commit', '[No Commit]')}"
            f" [NEEDS UPDATE]"
        )

    return (
        f" | Product: {p['product_submodule_version']:<10}"
        f" @ {p.get('product_submodule_commit', '[No Commit]')}"
    )


def print_final_reports(gitea_lists, categorized_packages, build_service):
    print("=" * 65)
    print(" GITEA REPOSITORY SYNC EVALUATIONS")
    print("=" * 65)

    print("\n### New Packages (Missing entirely from Gitea pool/. Request to BuildOps team) ###")
    if not gitea_lists["new_packages"]:
        print("  [None]")
    for p in gitea_lists["new_packages"]:
        print(
            f"  {p['name']:<40}"
            f" | OBS Version: {p['version']:<10}"
            f"{format_uv_lock_status(p)}"
            f"{format_product_submodule_status(p)}"
            f" | Origin: {p['origin']}"
        )

    print("\n### Factory Branch Match (Valid & Synced) ###")
    if not gitea_lists["factory_match"]:
        print("  [None]")
    for p in gitea_lists["factory_match"]:
        print(
            f"  {p['name']:<40}"
            f" | Matches Factory: {p['version']}"
            f"{format_uv_lock_status(p)}"
            f"{format_product_submodule_status(p)}"
        )

    print("\n### mlm-mcp-main Branch Match (Valid & Synced) ###")
    if not gitea_lists["mlm_main_match"]:
        print("  [None]")
    for p in gitea_lists["mlm_main_match"]:
        print(
            f"  {p['name']:<40}"
            f" | Matches mlm-mcp-main: {p['version']}"
            f"{format_uv_lock_status(p)}"
            f"{format_product_submodule_status(p)}"
        )

    print("\n### Packages Mismatched (Must be updated to Gitea with a Pull Request) ###")
    if not gitea_lists["mismatch_or_missing"]:
        print("  [None]")

    for p in gitea_lists["mismatch_or_missing"]:
        gitea_ver_str = ""
        if "factory_version" in p:
            gitea_ver_str = f" | Gitea Factory: {p['factory_version']:<10}"

        origin_ver_str = ""
        if p.get("suffix") in SUFFIX_MAPPING:
            origin_project = SUFFIX_MAPPING[p["suffix"]]
            origin_base_url = f"https://{build_service}/public/source/{origin_project}"
            _, origin_ver = fetch_obs_spec(origin_base_url, p["name"])
            if origin_ver and not origin_ver.startswith("["):
                origin_ver_str = f" | Origin Repo Ver: {origin_ver:<10}"

        print(
            f"  {p['name']:<40}"
            f" | OBS Target: {p['version']:<10}"
            f"{gitea_ver_str}"
            f"{origin_ver_str}"
            f"{format_uv_lock_status(p)}"
            f"{format_product_submodule_status(p)}"
            f" | Origin: {p['origin']}"
        )

    print("\n### ERROR SUMMARY: Packages containing Raw Macros in OBS Version Definition ###")
    if not categorized_packages["invalid_version"]:
        print("  [None]")

    for p in categorized_packages["invalid_version"]:
        saved = p in gitea_lists["factory_match"] or p in gitea_lists["mlm_main_match"]
        status = "[PASSED via Hash Sync Identity]" if saved else "[FAILED - Diverged File Structure]"
        print(
            f"  {p['name']:<40}"
            f" | Macro Found: {p['version']:<10}"
            f"{format_uv_lock_status(p)}"
            f"{format_product_submodule_status(p)}"
            f" | Status: {status}"
        )

    print("\n### uv.lock Version Mismatches ###")
    uv_mismatches = [
        p
        for packages in gitea_lists.values()
        for p in packages
        if p.get("uv_lock_mismatch")
    ]

    if not uv_mismatches:
        print("  [None]")

    for p in uv_mismatches:
        print(
            f"  {p['name']:<40}"
            f" | OBS Version: {p['version']:<10}"
            f" | uv.lock: {p.get('uv_lock_version', '[Unknown]'):<10}"
            f" | Action: update uv.lock or OBS staging"
        )

    print("\n### Product Submodule Version Mismatches ###")
    product_mismatches = [
        p
        for packages in gitea_lists.values()
        for p in packages
        if p.get("product_submodule_mismatch")
    ]

    if not product_mismatches:
        print("  [None]")

    for p in product_mismatches:
        print(
            f"  {p['name']:<40}"
            f" | OBS Version: {p['version']:<10}"
            f" | Product Version: {p.get('product_submodule_version', '[Unknown]'):<10}"
            f" | Commit: {p.get('product_submodule_commit', '[Unknown]')}"
            f" | Action: update product submodule pointer"
        )


def get_project_packages_and_versions(
    project_name,
    build_service,
    gitea_host,
    gitea_token,
    uv_lock_path=None,
    product_repo_path=None,
):
    base_url = f"https://{build_service}/public/source/{project_name}"
    gitea_url = f"https://{gitea_host}"
    gitea_headers = {"Authorization": f"token {gitea_token}"} if gitea_token else {}

    uv_lock_versions = load_uv_lock_versions(uv_lock_path)
    product_submodules = load_product_submodules(product_repo_path)

    categorized_packages = {suffix: [] for suffix in SUFFIX_MAPPING.keys()}
    categorized_packages.update({"updates": [], "standard": [], "invalid_version": []})

    gitea_lists = {
        "new_packages": [],
        "factory_match": [],
        "mlm_main_match": [],
        "mismatch_or_missing": [],
    }

    try:
        sys.stderr.write(f"Connecting to {build_service} to fetch package list...\n")
        response = requests.get(base_url, timeout=10)
        response.raise_for_status()

        root = ET.fromstring(response.text)
        all_pkgs = [entry.get("name") for entry in root.findall("entry") if entry.get("name")]

        test_pattern = re.compile(r"[-:]test(-py3\d+)?$")
        packages = [pkg for pkg in all_pkgs if not test_pattern.search(pkg)]

        total_count = len(packages)
        sys.stderr.write(f"Total packages to process: {total_count}\n")

        last_report_time = time.time()

        for idx, pkg in enumerate(packages, start=1):
            last_report_time = print_progress(idx, total_count, last_report_time)

            api_pkg_name = pkg[:-8] if pkg.endswith(":primary") else pkg
            obs_text, obs_version = fetch_obs_spec(base_url, api_pkg_name)
            obs_hash = calculate_hash(obs_text)

            clean_name, target_list, origin_repo, suffix_used = parse_package_metadata(pkg, project_name)

            package_data = {
                "name": clean_name,
                "raw_name": pkg,
                "version": obs_version,
                "origin": origin_repo,
                "suffix": suffix_used,
                "has_macro": "%" in obs_version or "[" in obs_version,
            }

            attach_uv_lock_status(package_data, uv_lock_versions)
            attach_product_submodule_status(
                gitea_url,
                gitea_headers,
                package_data,
                product_submodules,
            )

            list_key = "invalid_version" if package_data["has_macro"] else target_list
            categorized_packages[list_key].append(package_data)

            gitea_key = evaluate_gitea_sync(gitea_url, gitea_headers, package_data, obs_hash)
            gitea_lists[gitea_key].append(package_data)

        sys.stderr.write(f"[Progress] Completed 100% ({total_count}/{total_count})\n\n")
        print_final_reports(gitea_lists, categorized_packages, build_service)

        return gitea_lists, categorized_packages

    except Exception as e:
        sys.stderr.write(f"An error occurred: {e}\n")
        return None, None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Cross check OBS package targets against Gitea API workflows."
    )

    parser.add_argument("project", help="The name of the OBS project")
    parser.add_argument("-s", "--service", default="api.opensuse.org", help="The OBS instance domain")
    parser.add_argument("-g", "--gitea", default="src.opensuse.org", help="The Gitea host configuration domain")
    parser.add_argument("-t", "--gitea-token", default=os.getenv("GITEA_TOKEN"), help="Authorization Header Token")

    parser.add_argument(
        "--uv-lock",
        default=None,
        help="Optional path to uv.lock. If provided, package versions in uv.lock are compared with OBS versions.",
    )

    parser.add_argument(
        "--product-repo",
        default=None,
        help="Optional path to the product Git repository. If provided, product submodule commits are compared with OBS versions.",
    )

    args = parser.parse_args()

    gitea_results, obs_categories = get_project_packages_and_versions(
        project_name=args.project,
        build_service=args.service,
        gitea_host=args.gitea,
        gitea_token=args.gitea_token,
        uv_lock_path=args.uv_lock,
        product_repo_path=args.product_repo,
    )

    if gitea_results is None:
        sys.exit(2)

    drifts = len(gitea_results["new_packages"]) + len(gitea_results["mismatch_or_missing"])

    macro_failures = sum(
        1
        for p in obs_categories["invalid_version"]
        if p not in gitea_results["factory_match"]
        and p not in gitea_results["mlm_main_match"]
    )

    uv_lock_failures = sum(
        1
        for packages in gitea_results.values()
        for p in packages
        if p.get("uv_lock_mismatch")
    )

    product_submodule_failures = sum(
        1
        for packages in gitea_results.values()
        for p in packages
        if p.get("product_submodule_mismatch")
    )

    if drifts > 0 or macro_failures > 0 or uv_lock_failures > 0 or product_submodule_failures > 0:
        sys.stderr.write(
            f"\n[HEALTH CHECK] FAILED: Out of sync! "
            f"Found {drifts} structural drifts, "
            f"{macro_failures} macro failures, "
            f"{uv_lock_failures} uv.lock mismatches and "
            f"{product_submodule_failures} product submodule mismatches.\n"
        )
        sys.exit(1)

    sys.stderr.write("\n[HEALTH CHECK] PASSED: Sync ecosystem is 100% healthy.\n")
    sys.exit(0)

