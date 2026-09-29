#!/usr/bin/env python3
"""
GitLab Artifacts Download Script
Python port of the original bash script.
"""

import argparse
import getpass
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(format="%(message)s", level=logging.ERROR)
log = logging.getLogger(__name__)

GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
NC = "\033[0m"


def log_info(msg: str) -> None:
    log.info(f"{GREEN}[INFO]{NC} {msg}")


def log_warn(msg: str) -> None:
    log.warning(f"{YELLOW}[WARN]{NC} {msg}")


def log_error(msg: str) -> None:
    log.error(f"{RED}[ERROR]{NC} {msg}")


# ---------------------------------------------------------------------------
# Service → project-ID map
# ---------------------------------------------------------------------------
SERVICE_TO_PROJECT_ID_MAP: dict[str, int] = {
    # Malcolm IB project IDs
    "api": 18631,
    "arkime": 18632,
    "dashboards_helper": 18633,
    "dashboards": 18634,
    "dirinit": 18635,
    "file_monitor": 18636,
    "file_upload": 18637,
    "filebeat": 18638,
    "filescan": 18796,
    "freq": 18639,
    "htadmin": 18640,
    "keycloak": 18641,
    "logstash_oss": 18642,
    "netbox": 18643,
    "nginx": 18644,
    "opensearch": 18645,
    "pcap_capture": 18646,
    "pcap_monitor": 18647,
    "postgresql": 18648,
    "redis": 18649,
    "strelka_backend": 18797,
    "strelka_frontend": 18798,
    "strelka_manager": 18799,
    "suricata": 18650,
    "zeek": 18651,
    # Elastic IB project IDs
    "distribution": 18630,
    "edr_agent_store": 18470,
    "elastic_agent_fips": 18468,
    "elasticsearch_fips": 18062,
    "filebeat_fips": 18469,
    "kibana_fips": 18063,
    # Other IB project IDs
    "flux_cli": 18776,
    "gitea": 18694,
    "kafka": 18626,
    "kafka_ui": 18627,
    "kafka_operator": 18628,
    "mariadb_galera": 18699,
    "mariadb_operator": 18719,
    "misp_core": 17848,
    "misp_modules": 18066,
    "pgpool": 18766,
    "postgresql_repmgr": 18767,
    "valkey": 18768,
    "wiki": 18629,
}


# ---------------------------------------------------------------------------
# Environment file loader (replicates bash `source globalenviron / .envrc`)
# ---------------------------------------------------------------------------
def _expand_env_value(val: str) -> str:
    """
    Expand $VAR and ${VAR} references in val against os.environ.
    Unknown variables are left as-is (same as bash with unset vars).
    """

    def replacer(m: re.Match) -> str:
        var_name = m.group(1) or m.group(2)
        return os.environ.get(var_name, m.group(0))

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", replacer, val)


def load_env_file(path: Path) -> None:
    """
    Parse a simple KEY=VALUE env file (strips leading 'export ') and push
    values into os.environ.  $VAR / ${VAR} references in values are resolved
    against os.environ before storing.  Lines with complex bash syntax are skipped.
    """
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = re.sub(r"^export\s+", "", line)
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = _expand_env_value(val.strip().strip("'\""))
            if key and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                os.environ.setdefault(key, val)
    except OSError:
        pass


def load_local_env() -> None:
    # Follow symlinks so scripts installed via e.g. ~/.local/bin/ symlinks
    # still find the .envrc next to the real file, not next to the symlink.
    script_dir = Path(os.path.realpath(__file__)).parent
    for name in ("globalenviron", ".envrc"):
        candidate = script_dir / name
        if candidate.is_file():
            load_env_file(candidate)
            break


# ---------------------------------------------------------------------------
# Interactive prompts
# ---------------------------------------------------------------------------
def prompt_select_project() -> int:
    services = sorted(SERVICE_TO_PROJECT_ID_MAP)
    print("\nSelect a project:")
    for i, svc in enumerate(services, 1):
        print(f"  {i:2d}) {svc} (project ID: {SERVICE_TO_PROJECT_ID_MAP[svc]})")
    print()
    selection = input("Enter number or service name: ").strip()

    if selection.isdigit():
        idx = int(selection)
        if 1 <= idx <= len(services):
            svc = services[idx - 1]
            project_id = SERVICE_TO_PROJECT_ID_MAP[svc]
            log_info(f"PROJECT_ID set to {project_id} ({svc})")
            return project_id
        else:
            log_error(f"Invalid selection: {selection}")
            sys.exit(1)
    else:
        key = selection.replace("-", "_")
        if key in SERVICE_TO_PROJECT_ID_MAP:
            project_id = SERVICE_TO_PROJECT_ID_MAP[key]
            log_info(f"PROJECT_ID set to {project_id} ({key})")
            return project_id
        else:
            log_error(f"Unknown service: {selection}")
            sys.exit(1)


def prompt_if_unset(var_name: str, prompt_msg: str) -> str:
    val = os.environ.get(var_name, "")
    if val:
        if var_name == "GITLAB_ACCESS_TOKEN":
            log_info(f"{var_name} is already set (value hidden)")
        else:
            log_info(f"{var_name} is already set to '{val}'")
        return val

    if var_name == "GITLAB_ACCESS_TOKEN":
        val = getpass.getpass(prompt_msg)
        log_info(f"{var_name} has been set (value hidden for security)")
    else:
        val = input(prompt_msg).strip()
        log_info(f"{var_name} has been set to '{val}'")

    os.environ[var_name] = val
    return val


# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
def check_dependencies(load_image: bool, container_engine: str) -> None:
    if not shutil.which(container_engine):
        log_warn(f"{container_engine} not found in PATH — 'create-tar' jobs will fail")
    # requests, zipfile, json are stdlib / declared deps — no need to check at runtime


# ---------------------------------------------------------------------------
# GitLab API helpers
# ---------------------------------------------------------------------------
def make_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def get_job_info(gitlab_url: str, project_id: int, job_id: int, token: str) -> dict:
    url = f"{gitlab_url}/api/v4/projects/{project_id}/jobs/{job_id}"
    log_info(f"Fetching job information from {url}")
    resp = requests.get(url, headers=make_headers(token), allow_redirects=True, timeout=30)
    data = resp.json()
    if "message" in data:
        log_error(f"Failed to fetch job info: {data['message']}")
        sys.exit(1)
    job_name = data.get("name", "unknown")
    job_status = data.get("status", "unknown")
    log_info(f"Job: {job_name} (Status: {job_status})")
    if job_status != "success":
        log_warn(f"Job status is '{job_status}', not 'success'. Artifacts may not be available.")
    return data


def get_latest_job_id_by_name(
    gitlab_url: str,
    project_id: int,
    token: str,
    name: str,
    branch: str = "",
) -> tuple[int, str] | None:
    """
    Return (job_id, ref) for the most recent job matching name (and branch if given).
    Returns None if not found.
    """
    page = 1
    while True:
        resp = requests.get(
            f"{gitlab_url}/api/v4/projects/{project_id}/jobs",
            headers=make_headers(token),
            params={"per_page": 100, "page": page},
            timeout=30,
        )
        if resp.status_code == 401:
            log_error(f"401 Unauthorized fetching job list — check your token. Response: {resp.text[:200]}")
            return None
        if resp.status_code != 200:
            log_error(f"Unexpected HTTP {resp.status_code} fetching job list. Response: {resp.text[:200]}")
            return None
        jobs = resp.json()
        if not isinstance(jobs, list):
            log_error(f"Unexpected response format (expected list): {str(jobs)[:200]}")
            break

        for job in jobs:
            if job.get("name") != name:
                continue
            if branch and job.get("ref") != branch:
                continue
            return int(job["id"]), job.get("ref", "")

        next_page = resp.headers.get("X-Next-Page", "").strip()
        if not next_page:
            break
        page = int(next_page)

    return None


# ---------------------------------------------------------------------------
# Artifact download + extraction
# ---------------------------------------------------------------------------
def download_and_extract(
    gitlab_url: str,
    project_id: int,
    job_id: int,
    token: str,
    output_dir: Path,
    clean_output_dir: bool,
) -> list[Path]:
    """Download the artifact zip and extract it. Returns list of extracted files."""
    url = f"{gitlab_url}/api/v4/projects/{project_id}/jobs/{job_id}/artifacts"
    zip_path = output_dir / "artifacts.zip"

    if clean_output_dir and output_dir.exists():
        log_info(f"Cleaning output directory: {output_dir}")
        shutil.rmtree(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    log_info(f"Downloading artifacts from job {job_id}...")
    with requests.get(url, headers=make_headers(token), stream=True, allow_redirects=True, timeout=120) as resp:
        if resp.status_code == 404:
            log_error(f"Artifacts not found for job {job_id}. They may not exist or may have expired.")
            sys.exit(1)
        elif resp.status_code == 401:
            log_error("Authentication failed. Check your access token.")
            sys.exit(1)
        elif resp.status_code != 200:
            log_error(f"Failed to download artifacts. HTTP status: {resp.status_code}")
            sys.exit(1)

        with open(zip_path, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=8192):
                fh.write(chunk)

    log_info(f"Artifacts downloaded to: {zip_path}")
    log_info("Extracting artifacts...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(output_dir)

    extracted = [p for p in output_dir.rglob("*") if p.is_file() and p.name != "artifacts.zip"]
    log_info(f"Extracted {len(extracted)} file(s) to: {output_dir}")
    return extracted


# ---------------------------------------------------------------------------
# Job-specific post-processing handlers
# ---------------------------------------------------------------------------
def handle_create_tar(extracted: list[Path], output_dir: Path, container_engine: str, docker_image_tag: str) -> None:
    load_docker_image(output_dir, container_engine, docker_image_tag)


# Severity order for display
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]


def _normalize_severity(s: str) -> str:
    return s.strip().capitalize() if s else "Unknown"


def _summarize_vat_image(image: dict, is_parent: bool) -> dict:
    """Extract the summary fields from a VAT image dict into a plain Python dict."""
    from collections import defaultdict

    name = image.get("imageName", "?")
    tag = image.get("tag", "?")
    state = image.get("state", {})
    factors = state.get("factors", {})
    by_sev: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in image.get("findings", []):
        sev = _normalize_severity(f.get("severity", ""))
        status = f.get("state", {}).get("findingStatus", "Unknown")
        by_sev[sev][status] += 1
    findings_summary = {sev: dict(by_sev[sev]) for sev in SEVERITY_ORDER if sev in by_sev}
    raw_findings = image.get("findings", [])
    return {
        "isParent": is_parent,
        "imageName": name,
        "tag": tag,
        "built": image.get("snapshot", {}).get("built", "?"),
        "vatUrl": image.get("vatUrl", ""),
        "abc": state.get("abc", "?"),
        "ora": state.get("ora", "?"),
        "percentVerified": state.get("percentVerified", "?"),
        "issues": factors.get("abc", {}).get("issues", []),
        "findings": findings_summary,
        "raw_findings": raw_findings,
    }


def _print_vat_image(summary: dict, long_output: bool = False, status_filter: list[str] | None = None) -> None:
    """Print a pre-summarized VAT image dict in human-readable form."""
    import textwrap

    label = f"{summary['imageName']}:{summary['tag']}"
    suffix = " (parent)" if summary["isParent"] else ""
    print(f"\n=== {label}{suffix} ===")
    print(f"  Image:            {label}")
    print(f"  Built:            {summary['built']}")
    print(f"  VAT URL:          {summary['vatUrl']}")
    print(f"  ABC:              {summary['abc']}")
    print(f"  ORA:              {summary['ora']}")
    print(f"  % Verified:       {summary['percentVerified']}")
    issues = summary["issues"]
    if issues:
        print(f"  Issues:")
        for issue in issues:
            print(f"    - {issue}")
    else:
        print(f"  Issues:           none")
    findings = summary["findings"]
    if not findings:
        print(f"  Findings:         none")
        return
    print(f"  Findings:")
    for sev in SEVERITY_ORDER:
        if sev not in findings:
            continue
        statuses = findings[sev]
        total = sum(statuses.values())
        parts = ", ".join(f"{count} {status}" for status, count in sorted(statuses.items()))
        print(f"    {sev:<10} {total:>3}  ({parts})")
        if not long_output:
            continue
        # Individual findings for this severity, filtered by status
        sev_findings = [
            f
            for f in summary["raw_findings"]
            if _normalize_severity(f.get("severity", "")) == sev
            and (
                not status_filter
                or f.get("state", {}).get("findingStatus", "").lower() in {s.lower() for s in status_filter}
            )
        ]
        for f in sev_findings:
            fid = f.get("findingId", "?")
            identifier = f.get("identifier", "?")
            package = f.get("package", "?")
            pkg_path = f.get("packagePath") or ""
            status = f.get("state", {}).get("findingStatus", "?")
            desc = (f.get("description") or "").strip()
            pkg_str = f"{package}  {pkg_path}" if pkg_path else package
            just = (f.get("justificationGate") or {}).get("justification", "").strip()
            print(f"      [{fid}] {identifier}  {pkg_str}  ({status})")
            if desc:
                for line in textwrap.wrap(desc, width=100, initial_indent="        ", subsequent_indent="        "):
                    print(line)
            if just:
                print(f"        Justification: ", end="")
                just_lines = textwrap.wrap(just, width=100, subsequent_indent="          ")
                print("\n          ".join(just_lines))


def _collect_vat_images(ordered: list) -> list[tuple[dict, bool]]:
    """
    Parse the ordered list of (filename, Path) tuples and return
    [(image_dict, is_parent), ...] in display order.
    """
    result = []
    for filename, json_file in ordered:
        try:
            data = json.loads(json_file.read_text())
        except json.JSONDecodeError as e:
            log_error(f"Failed to parse {json_file}: {e}")
            continue
        if "image" in data:
            result.append((data["image"], False))
        elif "images" in data:
            for entry in data.get("images", []):
                img = entry.get("image", {})
                if img:
                    result.append((img, True))
        # else: unrecognized structure (e.g. vat_request.json) — silently skip
    return result


def handle_vat(
    extracted: list[Path],
    output_format: str = "text",
    show_parent: bool = False,
    long_output: bool = False,
    status_filter: list[str] | None = None,
) -> None:
    json_files = {f.name: f for f in extracted if f.suffix.lower() == ".json"}
    if not json_files:
        log_warn("No JSON files found in VAT artifacts.")
        return

    # Process vat_response.json first, then parent_vat_response.json, then any others
    ordered: list[tuple[str, Path]] = []
    for priority in ("vat_response.json", "parent_vat_response.json"):
        if priority in json_files:
            ordered.append((priority, json_files.pop(priority)))
    for name, path in sorted(json_files.items()):
        ordered.append((name, path))

    images = _collect_vat_images(ordered)
    if not images:
        return

    summaries = [_summarize_vat_image(img, is_parent) for img, is_parent in images]
    if not show_parent:
        summaries = [s for s in summaries if not s["isParent"]]

    if output_format == "json":
        out = {}
        for s in summaries:
            key = f"{s['imageName']}:{s['tag']}"
            entry = {k: v for k, v in s.items() if k != "raw_findings"}
            if long_output:
                entry["findings_detail"] = [
                    {
                        "findingId": f.get("findingId"),
                        "identifier": f.get("identifier"),
                        "severity": _normalize_severity(f.get("severity", "")),
                        "package": f.get("package"),
                        "packagePath": f.get("packagePath"),
                        "status": f.get("state", {}).get("findingStatus"),
                        "description": f.get("description"),
                        "justification": (f.get("justificationGate") or {}).get("justification"),
                    }
                    for f in s["raw_findings"]
                    if not status_filter
                    or f.get("state", {}).get("findingStatus", "").lower() in {s.lower() for s in status_filter}
                ]
            out[key] = entry
        print(json.dumps(out, indent=2))
    else:
        for s in summaries:
            _print_vat_image(s, long_output=long_output, status_filter=status_filter)


def handle_unknown_job(job_name: str, extracted: list[Path]) -> None:
    log_info(f"No specific handler for job '{job_name}'. Files in artifact zip:")
    for f in extracted:
        log_info(f"  {f.name}")


def dispatch_job(
    job_name: str,
    extracted: list[Path],
    output_dir: Path,
    container_engine: str,
    docker_image_tag: str,
    output_format: str = "text",
    show_parent: bool = False,
    long_output: bool = False,
    status_filter: list[str] | None = None,
) -> None:
    if job_name == "create-tar":
        handle_create_tar(extracted, output_dir, container_engine, docker_image_tag)
    elif job_name == "vat":
        handle_vat(
            extracted,
            output_format=output_format,
            show_parent=show_parent,
            long_output=long_output,
            status_filter=status_filter,
        )
    else:
        handle_unknown_job(job_name, extracted)


# ---------------------------------------------------------------------------
# Docker image load
# ---------------------------------------------------------------------------
def load_docker_image(output_dir: Path, container_engine: str, image_tag: str) -> None:
    log_info(f"Looking for {container_engine} image in extracted artifacts...")

    # Prefer ci-artifacts/tar/**/*.tar
    tar_file: Path | None = None
    candidates = list(output_dir.glob("**/ci-artifacts/tar/**/*.tar"))
    if candidates:
        tar_file = candidates[0]
    else:
        log_warn(f"No tar found under ci-artifacts/tar/; falling back to any *.tar in {output_dir}")
        all_tars = list(output_dir.rglob("*.tar"))
        if all_tars:
            tar_file = all_tars[0]

    if tar_file is None:
        log_error(f"No {container_engine} tar file found in artifacts (searched: {output_dir})")
        return

    log_info(f"Using tar file: {tar_file}")

    # Derive a default tag from the filename if none was provided
    if not image_tag:
        stem = tar_file.stem  # e.g. misp-modules-4698286-amd64
        default_name = re.sub(r"-\d+.*$", "", stem)  # -> misp-modules
        if default_name == stem:  # no -<digits> found, drop last segment
            default_name = stem.rsplit("-", 1)[0]
        image_tag = f"{default_name}-cibuild:latest"
        log_info(f"No {container_engine} image tag provided; defaulting to: {image_tag}")

    log_info(f"Loading {container_engine} image...")
    result = subprocess.run(
        [container_engine, "load", "-i", str(tar_file)],
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        log_error(f"Failed to load {container_engine} image from: {tar_file}\n{result.stderr}")
        return

    # Parse "Loaded image: repo/name:tag"  or  "Loaded image ID: sha256:..."
    loaded_ref = ""
    m = re.search(r"Loaded image: (.+)", result.stdout)
    if m:
        loaded_ref = m.group(1).strip()
    else:
        m = re.search(r"Loaded image ID: (.+)", result.stdout)
        if m:
            loaded_ref = m.group(1).strip()

    if not loaded_ref:
        log_error(f"{container_engine} load output did not contain 'Loaded image:' or 'Loaded image ID:'; not tagging.")
        return

    log_info(f"Loaded image reference: {loaded_ref}")
    log_info(f"Tagging image as: {image_tag}")
    tag_result = subprocess.run(
        [container_engine, "tag", loaded_ref, image_tag],
        capture_output=True,
        text=True,
    )
    if tag_result.returncode != 0:
        log_error(f"Failed to tag image: {tag_result.stderr}")
        return

    log_info(f"Successfully tagged image as: {image_tag}")

    inspect_result = subprocess.run(
        [container_engine, "inspect", image_tag],
        capture_output=True,
        text=True,
    )
    if inspect_result.returncode == 0:
        try:
            log_info(json.dumps(json.loads(inspect_result.stdout), indent=2))
        except json.JSONDecodeError:
            log_info(inspect_result.stdout)


# ---------------------------------------------------------------------------
# Config resolution helpers
# ---------------------------------------------------------------------------
def resolve_project_id(raw: str) -> int | None:
    """
    If raw is all digits, return it as int.
    Otherwise treat as service name (normalising - → _) and look up the map.
    Returns None if it's a name that isn't in the map.
    """
    if raw.isdigit():
        return int(raw)
    key = raw.replace("-", "_")
    pid = SERVICE_TO_PROJECT_ID_MAP.get(key)
    if pid is None:
        return None
    return pid


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="GitLab Artifacts Downloader",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-g", "--gitlab", dest="gitlab_url", help="GitLab URL")
    parser.add_argument("-p", "--project-id", dest="project_id", help="GitLab project ID or service name")
    parser.add_argument("-b", "--project-branch", dest="project_branch", help="GitLab project branch name")
    parser.add_argument("-j", "--job-id", dest="job_id", help="GitLab job ID (or job name)")
    parser.add_argument("-t", "--tag", dest="docker_image_tag", help="Docker image tag to apply after loading")
    parser.add_argument("-k", "--token", dest="token", help="GitLab access token")
    parser.add_argument("-o", "--output-dir", dest="output_dir", help="Output directory (default: temp dir)")
    parser.add_argument(
        "-l",
        "--log-level",
        dest="log_level",
        default="error",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Log level (default: error)",
    )
    parser.add_argument(
        "-f",
        "--output-format",
        dest="output_format",
        default="text",
        choices=["text", "json"],
        help="Output format for VAT results (default: text)",
    )
    parser.add_argument(
        "-P",
        "--show-parent",
        dest="show_parent",
        action="store_true",
        help="Include parent image(s) in VAT output (default: off)",
    )
    parser.add_argument(
        "-L", "--long", dest="long_output", action="store_true", help="Show individual findings detail (VAT job)"
    )
    parser.add_argument(
        "-S",
        "--status",
        dest="status_filter",
        action="append",
        metavar="STATUS",
        help="Filter findings by status (repeatable); e.g. 'Needs Justification'. "
        "Only applies with --long. If omitted, all statuses shown.",
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    load_local_env()

    # CLI args win over env; env already loaded above via load_local_env()
    gitlab_url = args.gitlab_url or os.environ.get("GITLAB_URL", "")
    project_id_raw = args.project_id or os.environ.get("PROJECT_ID", "")
    project_branch = args.project_branch or os.environ.get("PROJECT_BRANCH", "")
    job_id_raw = args.job_id or os.environ.get("JOB_ID", "")
    docker_image_tag = args.docker_image_tag or os.environ.get("DOCKER_IMAGE_TAG", "")
    token = args.token or os.environ.get("GITLAB_ACCESS_TOKEN", "")

    container_engine = os.environ.get("CONTAINER_ENGINE", "docker")
    output_dir_str = args.output_dir or os.environ.get("OUTPUT_DIR", "")
    clean_output_dir = os.environ.get("CLEAN_OUTPUT_DIR", "true").lower() == "true"

    if output_dir_str:
        output_dir = Path(output_dir_str)
        _tmp_dir = None
    else:
        _tmp_dir = tempfile.mkdtemp(prefix="gitlab-artifacts-")
        output_dir = Path(_tmp_dir)
        log_info(f"OUTPUT_DIR not set; using temp directory: {output_dir}")

    # --- Interactive prompts for missing required values ---
    # These must all happen before any API calls.
    if not gitlab_url:
        gitlab_url = prompt_if_unset("GITLAB_URL", "Please enter the GitLab URL: ")
    else:
        log_info(f"GITLAB_URL is already set to '{gitlab_url}'")

    if not token:
        token = prompt_if_unset("GITLAB_ACCESS_TOKEN", "Please enter your GitLab access token: ")
    else:
        log_info("GITLAB_ACCESS_TOKEN is already set (value hidden)")

    # Project ID resolution
    project_id: int
    if project_id_raw:
        resolved = resolve_project_id(project_id_raw)
        if resolved is None:
            log_warn(f"Service name '{project_id_raw}' not found in map; prompting for project selection.")
            project_id = prompt_select_project()
        else:
            project_id = resolved
            log_info(f"PROJECT_ID is already set to '{project_id}'")
    else:
        project_id = prompt_select_project()

    # Job ID resolution (name → numeric ID)
    # All prompts and env reads are done above; now we can make API calls.
    job_id: int
    if job_id_raw and not job_id_raw.isdigit():
        old_job_id = job_id_raw
        result = get_latest_job_id_by_name(gitlab_url, project_id, token, old_job_id, project_branch)
        if result:
            job_id, ref = result
            log_info(f'Found "{job_id}" (in "{ref}") as most recent job for "{old_job_id}"')
        else:
            log_warn(f'Did not find most recent job for "{old_job_id}"')
            # Name lookup failed — clear the env var so we prompt cleanly for a raw ID
            os.environ.pop("JOB_ID", None)
            job_id_str = input("Please enter the GitLab job ID from repo: ").strip()
            job_id = int(job_id_str)
    elif job_id_raw.isdigit():
        job_id = int(job_id_raw)
        log_info(f"JOB_ID is already set to '{job_id}'")
    else:
        job_id_str = prompt_if_unset("JOB_ID", "Please enter the GitLab job ID from repo: ")
        job_id = int(job_id_str)

    # --- Validation ---
    errors = []
    if not gitlab_url:
        errors.append("GITLAB_URL is not set")
    if not token:
        errors.append("GITLAB_ACCESS_TOKEN is not set")
    if errors:
        for e in errors:
            log_error(e)
        sys.exit(1)

    check_dependencies(load_image=True, container_engine=container_engine)

    # --- Summary ---
    log_info("GitLab Artifacts Downloader")
    log_info("==========================")
    log_info("Configuration:")
    log_info(f"  GitLab URL:       {gitlab_url}")
    log_info(f"  Project ID:       {project_id}")
    log_info(f"  Job ID:           {job_id}")
    log_info(f"  Output Directory: {output_dir}")
    if docker_image_tag:
        log_info(f"  {container_engine} Image Tag (preconfigured): {docker_image_tag}")

    job_info = get_job_info(gitlab_url, project_id, job_id, token)
    job_name = job_info.get("name", "")
    log_info(f"  Job name:         {job_name}")

    extracted = download_and_extract(
        gitlab_url=gitlab_url,
        project_id=project_id,
        job_id=job_id,
        token=token,
        output_dir=output_dir,
        clean_output_dir=clean_output_dir,
    )

    dispatch_job(
        job_name=job_name,
        extracted=extracted,
        output_dir=output_dir,
        container_engine=container_engine,
        docker_image_tag=docker_image_tag,
        output_format=args.output_format,
        show_parent=args.show_parent,
        long_output=args.long_output,
        status_filter=args.status_filter,
    )

    log_info("Download completed successfully!")

    if _tmp_dir:
        shutil.rmtree(_tmp_dir, ignore_errors=True)
        log_info(f"Removed temp directory: {_tmp_dir}")


if __name__ == "__main__":
    main()
