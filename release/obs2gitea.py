import argparse
import base64
import hashlib
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
import requests

# Constant mapping for known repository suffixes
SUFFIX_MAPPING = {
    "dlp": "devel:languages:python",
    "dlpb": "devel:languages:python:backports",
    "dlpn": "devel:languages:python:numeric",
    "Mf": "M17N:fonts",
    "dtc": "devel:tools:compiler",
}

def extract_spec_version(spec_text):
    """Extracts the Version value from a raw spec file string."""
    if not spec_text:
        return None
    version_match = re.search(r'(?i)^Version:\s*([^\s#]+)', spec_text, re.MULTILINE)
    return version_match.group(1) if version_match else None

def calculate_hash(text):
    """Returns the SHA-256 hash of a text string."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest() if text else ""

def get_gitea_spec_content_and_version(gitea_url, repo_name, branch, headers):
    """Fetches a spec file's text and extracted version from Gitea."""
    url = f"{gitea_url}/api/v1/repos/pool/{repo_name}/contents/{repo_name}.spec"
    try:
        response = requests.get(url, params={"ref": branch}, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            spec_text = (
                base64.b64decode(data["content"]).decode('utf-8', errors='ignore')
                if isinstance(data, dict) and "content" in data
                else response.text
            )
            return spec_text, extract_spec_version(spec_text)
    except Exception:
        pass
    return None, None

def print_progress(idx, total_count, last_report_time, report_interval=5.0):
    """Prints a linear progress update to stderr suitable for CI buffering."""
    current_time = time.time()
    if current_time - last_report_time >= report_interval:
        percentage = (idx / total_count) * 100
        sys.stderr.write(f"[Progress] Processed {idx}/{total_count} packages ({percentage:.1f}%)\n")
        sys.stderr.flush()
        return current_time
    return last_report_time

def parse_package_metadata(raw_pkg_name, project_name):
    """
    Cleans an OBS package name, strips target suffixes/flags, and 
    determines its logical upstream repository origin.
    """
    pkg_clean = raw_pkg_name.strip()
    has_primary = pkg_clean.endswith(":primary")
    base_str = pkg_clean[:-8] if has_primary else pkg_clean

    # Updated fallback string to reference the dynamic target project argument
    origin_repo = f"New Package from {project_name} (No suffix origin)"
    target_list = "standard"
    clean_name = base_str

    if base_str.endswith(".new"):
        target_list = "updates"
        name_without_new = base_str[:-4]
        origin_repo = "Unknown Update"
        
        suffix_match = re.search(r'\.(dlp|dlpb|dlpn|Mf|dtc)$', name_without_new)
        if suffix_match:
            found_sfx = suffix_match.group(1)
            clean_name = name_without_new[:suffix_match.start()]
            origin_repo = f"Update for {SUFFIX_MAPPING[found_sfx]}"
        else:
            clean_name = name_without_new
    else:
        suffix_match = re.search(r'\.(dlp|dlpb|dlpn|Mf|dtc)$', base_str)
        if suffix_match:
            found_sfx = suffix_match.group(1)
            clean_name = base_str[:suffix_match.start()]
            target_list = found_sfx
            origin_repo = f"From {SUFFIX_MAPPING[found_sfx]}"

    return clean_name, target_list, origin_repo

def fetch_obs_spec(base_url, api_pkg_name):
    """Fetches the raw spec file content and version from OBS for a specific package."""
    pkg_url = f"{base_url}/{api_pkg_name}"
    try:
        response = requests.get(pkg_url, timeout=10)
        if response.status_code != 200:
            return None, "[Error fetching package directory]"
            
        root = ET.fromstring(response.text)
        files = [entry.get('name') for entry in root.findall('entry') if entry.get('name')]
        spec_file = next((f for f in files if f.endswith('.spec')), None)
        
        if not spec_file:
            return None, "[No .spec file found]"
            
        spec_response = requests.get(f"{pkg_url}/{spec_file}", timeout=10)
        if spec_response.status_code == 200:
            return spec_response.text, extract_spec_version(spec_response.text) or "[Version tag not found]"
    except Exception:
        pass
    return None, "[Error fetching spec file]"

def evaluate_gitea_sync(gitea_url, headers, pkg_data, obs_hash):
    """Queries Gitea and evaluates whether a package matches, drifts, or is entirely missing."""
    repo_url = f"{gitea_url}/api/v1/repos/pool/{pkg_data['name']}"
    response = requests.get(repo_url, headers=headers, timeout=5)
    
    if response.status_code == 404:
        return "new_packages"
        
    if response.status_code == 200:
        f_text, f_ver = get_gitea_spec_content_and_version(gitea_url, pkg_data['name'], "factory", headers)
        m_text, m_ver = get_gitea_spec_content_and_version(gitea_url, pkg_data['name'], "mlm-mcp-main", headers)
        
        f_hash = calculate_hash(f_text)
        m_hash = calculate_hash(m_text)

        # 1. Check exact cryptographic layout match (handles macros)
        if obs_hash and obs_hash == f_hash:
            return "factory_match"
        if obs_hash and obs_hash == m_hash:
            return "mlm_main_match"
        
        # 2. Check version equality (flag content drift if text mismatch)
        if not pkg_data["has_macro"] and pkg_data["version"] in (f_ver, m_ver):
            pkg_data["version"] += " [Content Drift]"
            return "mismatch_or_missing"
            
        if pkg_data["has_macro"]:
            pkg_data["version"] += " [Macro Diverged]"

    return "mismatch_or_missing"

def print_final_reports(gitea_lists, categorized_packages):
    """Outputs clear tabular synchronization breakdowns to stdout."""
    print("=" * 65)
    print(" GITEA REPOSITORY SYNC EVALUATIONS")
    print("=" * 65)

    print("\n### New Packages (Missing entirely from Gitea pool/. Request to BuildOps team) ###")
    if not gitea_lists["new_packages"]: print("  [None]")
    for p in gitea_lists["new_packages"]:
        print(f"  {p['name']:<40} | OBS Version: {p['version']:<10} | Origin: {p['origin']}")

    print("\n### Factory Branch Match (Valid & Synced) ###")
    if not gitea_lists["factory_match"]: print("  [None]")
    for p in gitea_lists["factory_match"]:
        print(f"  {p['name']:<40} | Matches Factory: {p['version']}")

    print("\n### mlm-mcp-main Branch Match (Valid & Synced) ###")
    if not gitea_lists["mlm_main_match"]: print("  [None]")
    for p in gitea_lists["mlm_main_match"]:
        print(f"  {p['name']:<40} | Matches mlm-mcp-main: {p['version']}")

    print("\n### Packages Mismatched (Must be updated to Gitea with a Pull Request) ###")
    if not gitea_lists["mismatch_or_missing"]: print("  [None]")
    for p in gitea_lists["mismatch_or_missing"]:
        print(f"  {p['name']:<40} | OBS Target: {p['version']:<10} | Origin: {p['origin']}")

    print("\n### ERROR SUMMARY: Packages containing Raw Macros in OBS Version Definition (Must be updated to Gitea with a Pull Request) ###")
    if not categorized_packages["invalid_version"]: print("  [None]")
    for p in categorized_packages["invalid_version"]:
        saved = p in gitea_lists["factory_match"] or p in gitea_lists["mlm_main_match"]
        status = "[PASSED via Hash Sync Identity]" if saved else "[FAILED - Diverged File Structure]"
        print(f"  {p['name']:<40} | Macro Found: {p['version']:<10} | Status: {status}")

def get_project_packages_and_versions(project_name, build_service, gitea_host, gitea_token):
    """Orchestrates the data collection lifecycle across OBS and Gitea."""
    base_url = f"https://{build_service}/public/source/{project_name}"
    gitea_url = f"https://{gitea_host}"
    gitea_headers = {"Authorization": f"token {gitea_token}"} if gitea_token else {}

    categorized_packages = {suffix: [] for suffix in SUFFIX_MAPPING.keys()}
    categorized_packages.update({"updates": [], "standard": [], "invalid_version": []})

    gitea_lists = {"new_packages": [], "factory_match": [], "mlm_main_match": [], "mismatch_or_missing": []}

    try:
        sys.stderr.write(f"Connecting to {build_service} to fetch package list...\n")
        response = requests.get(base_url, timeout=10)
        response.raise_for_status()
        
        root = ET.fromstring(response.text)
        all_pkgs = [entry.get('name') for entry in root.findall('entry') if entry.get('name')]
        
        test_pattern = re.compile(r'[-:]test(-py3\d+)?$')
        packages = [pkg for pkg in all_pkgs if not test_pattern.search(pkg)]
        total_count = len(packages)
        sys.stderr.write(f"Total packages to process: {total_count}\n")

        last_report_time = time.time()

        for idx, pkg in enumerate(packages, start=1):
            last_report_time = print_progress(idx, total_count, last_report_time)

            # 1. Download source from OBS
            api_pkg_name = pkg[:-8] if pkg.endswith(":primary") else pkg
            obs_text, obs_version = fetch_obs_spec(base_url, api_pkg_name)
            obs_hash = calculate_hash(obs_text)

            # 2. Extract and sanitize package parameters (Now passing the project_name parameter)
            clean_name, target_list, origin_repo = parse_package_metadata(pkg, project_name)
            
            package_data = {
                "name": clean_name, "raw_name": pkg, "version": obs_version,
                "origin": origin_repo, "has_macro": "%" in obs_version or "[" in obs_version
            }

            # 3. Handle list distributions
            list_key = "invalid_version" if package_data["has_macro"] else target_list
            categorized_packages[list_key].append(package_data)

            # 4. Run Gitea validations and group them
            gitea_key = evaluate_gitea_sync(gitea_url, gitea_headers, package_data, obs_hash)
            gitea_lists[gitea_key].append(package_data)

        sys.stderr.write(f"[Progress] Completed 100% ({total_count}/{total_count})\n\n")
        print_final_reports(gitea_lists, categorized_packages)
        return gitea_lists, categorized_packages

    except Exception as e:
        sys.stderr.write(f"An error occurred: {e}\n")
        return None, None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cross check OBS package targets against Gitea API workflows.")
    parser.add_argument("project", help="The name of the OBS project")
    parser.add_argument("-s", "--service", default="api.opensuse.org", help="The OBS instance domain")
    parser.add_argument("-g", "--gitea", default="src.opensuse.org", help="The Gitea host configuration domain")
    parser.add_argument("-t", "--gitea-token", default=os.getenv("GITEA_TOKEN"), help="Authorization Header Token")

    args = parser.parse_args()
    
    gitea_results, obs_categories = get_project_packages_and_versions(
        project_name=args.project, build_service=args.service, 
        gitea_host=args.gitea, gitea_token=args.gitea_token
    )
    
    if gitea_results is None:
        sys.exit(2)
        
    drifts = len(gitea_results["new_packages"]) + len(gitea_results["mismatch_or_missing"])
    macro_failures = sum(1 for p in obs_categories["invalid_version"] if p not in gitea_results["factory_match"] and p not in gitea_results["mlm_main_match"])
    
    if drifts > 0 or macro_failures > 0:
        sys.stderr.write(f"\n[HEALTH CHECK] FAILED: Out of sync! Found {drifts} structural drifts and {macro_failures} macro failures.\n")
        sys.exit(1)
    
    sys.stderr.write("\n[HEALTH CHECK] PASSED: Sync ecosystem is 100% healthy.\n")
    sys.exit(0)