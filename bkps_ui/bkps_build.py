#!/usr/bin/env python3
"""Clone, build, or install BKPS artifacts into the deployment directory."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import glob
import shutil
from pathlib import Path
from bkps_config import Config, normalize_project_paths
from bkps_config import is_bkps_source_checkout, detect_embedded_bkps_repo
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import run, stream, get_output
from bkps_deps import build_native_dependencies
# ── Constants ────────────────────────────────────────────────────────────────

# Canonical upstream repository for all BKPS source builds.
# Override per checkout with Config.bkps_repo_url (BKPS_REPO_URL in conf).
BKPS_REPO_URL = "https://github.com/altera-fpga/device-security-software-services.git"


def _clone_repo_url(cfg: Config) -> str:
    """Return the Git URL used to clone DSSS for this config."""
    override = (getattr(cfg, "bkps_repo_url", "") or "").strip()
    return override or BKPS_REPO_URL

# ── Build phase ──────────────────────────────────────────────────────────────
# ── LOCAL-FILE OVERRIDE (TEMP WORKAROUND) ──────────────────────────────────
# Rewrites the Gradle wrapper's distributionUrl to point at a locally-provided
# gradle-*-bin.zip so operators without internet access (or on a proxy that
# blocks services.gradle.org) can still build.  A no-op when the override is
# empty.  Grep for `local_override_` to remove cleanly.
def _apply_local_gradle_zip_override(cfg: Config) -> None:
    override = (getattr(cfg, "local_override_gradle_zip", "") or "").strip()
    if not override:
        return

    if not os.path.isfile(override):
        raise RuntimeError(
            f"local_override_gradle_zip points at a file that does not exist: {override}"
        )

    props_path = os.path.join(
        cfg.bkps_repo_dir, "gradle", "wrapper", "gradle-wrapper.properties"
    )
    if not os.path.isfile(props_path):
        print_warning(
            f"local_override_gradle_zip is set but gradle-wrapper.properties "
            f"was not found at {props_path} — skipping override."
        )
        return

    # Build the file:/// URL the Gradle wrapper expects.  urllib.request.pathname2url
    # handles Windows drive letters, spaces, and parentheses correctly.
    import urllib.request as _urlreq
    file_url = "file:" + _urlreq.pathname2url(os.path.abspath(override))

    with open(props_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    changed = False
    new_lines = []
    for line in lines:
        if line.startswith("distributionUrl="):
            new_line = f"distributionUrl={file_url}\n"
            if new_line != line:
                changed = True
            new_lines.append(new_line)
        else:
            new_lines.append(line)

    if changed:
        with open(props_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        print_info(
            f"  [override] gradle-wrapper.properties distributionUrl -> {file_url}"
        )
    else:
        print_info(
            f"  [override] gradle-wrapper.properties already points at {file_url}"
        )


# The wrapper's GNU branch leads the conditional in some releases and follows a
# MinGW branch in others, so it is matched by its condition rather than by its
# position.
_GNU_LINK_BRANCH = re.compile(
    r"(?ms)^[ \t]*(?:else)?if[ \t]*\([ \t]*CMAKE_COMPILER_IS_GNUC"
    r".*?(?=^[ \t]*(?:elseif|else|endif)[ \t]*\()"
)


def _apply_linux_spdm_wrapper_malloc_link(repo_dir: str) -> None:
    """Link libspdm's malloc stub into the wrapper's GNU compiler branch.

    ``allocate_pool`` and ``free_pool`` are implemented in ``libmalloclib.a``.
    The repository links it in the MinGW and MSVC branches but omits it from the
    GNU branch, and ELF permits a shared object with undefined symbols, so the
    Linux wrapper is produced incomplete. The JVM loads with lazy binding, which
    would defer the failure to the first libspdm allocation during attestation.
    """
    if sys.platform.startswith("win"):
        return

    path = os.path.join(repo_dir, "spdm_wrapper", "wrapper", "CMakeLists.txt")
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(
            f"SPDM wrapper CMake file could not be read: {path}: {exc}"
        ) from exc

    branch = _GNU_LINK_BRANCH.search(text)
    if not branch:
        raise RuntimeError(
            "SPDM wrapper CMake file has no GNU compiler branch, so the "
            f"reviewed link fix cannot be applied: {path}"
        )
    if "malloclib" in branch.group(0):
        print_info("SPDM wrapper already links the libspdm malloc stub")
        return

    call = re.search(r"target_link_libraries\s*\(", branch.group(0))
    if not call:
        raise RuntimeError(
            "SPDM wrapper GNU branch has no target_link_libraries call: " + path
        )

    opening = branch.start() + call.end() - 1
    depth = 0
    closing = -1
    for index in range(opening, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing < 0:
        raise RuntimeError(
            "SPDM wrapper GNU link list is not closed: " + path
        )

    # GNU ld resolves static archives in order, so the stub goes last, after
    # the libspdm archives that reference it. This mirrors the MinGW branch.
    patched = (
        text[:closing]
        + "\n            ${LIBSPDM_LIB_DIR}/libmalloclib.a"
        + text[closing:]
    )
    Path(path).write_text(patched, encoding="utf-8")
    print_success("Linked the libspdm malloc stub into the Linux SPDM wrapper")


def build_all(cfg: Config) -> None:
    """Clone the repo if needed, build native dependencies, and copy artifacts to cfg.bkps_dir."""
    print_header("Building BKPS from Source")
    try:
        project_dir, repo_dir = normalize_project_paths(cfg, require_project=True)
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc

    print_info(f"BKPS project directory: {project_dir}")
    print_info(f"BKPS source checkout: {repo_dir}")
    print_info(
        "Requested build: "
        + (
            "full repository"
            if getattr(cfg, "bkps_build_mode", "bkp_only") == "full"
            else "BKP only"
        )
        + (
            " + BKP Programmer"
            if bool(getattr(cfg, "include_bkp_programmer", False))
            else ""
        )
    )
    if not os.path.isdir(cfg.bkps_repo_dir):
        print_step(1, "Cloning BKPS repository...")

        run([
            "git", "clone",
            _clone_repo_url(cfg),
            cfg.bkps_repo_dir,
        ])
        print_success("Repository cloned")

        print_step(2, "Detecting and checking out release...")
        print_info("Selecting release branch...")
        branches = get_output(
            ["git", "branch", "-r"],
            cwd=cfg.bkps_repo_dir
        )

        release = cfg.bkps_release
        if release == "":
            if any(b.strip() == "origin/master" for b in branches.splitlines()):
                release = "origin/master"

        if not release:
            raise RuntimeError("Could not detect any valid branch")

        print_info(f"Checking out: {release}")
        run(["git", "checkout", release], cwd=cfg.bkps_repo_dir)
        print_success(f"Checked out {release}")

        print_step(3, "Initializing git submodules...")
        # This is required for libspdm and other dependencies
        run(["git", "submodule", "update", "--init", "--recursive"], cwd=cfg.bkps_repo_dir)
        print_success("Submodules initialized")
    elif is_bkps_source_checkout(cfg.bkps_repo_dir):
        embedded = detect_embedded_bkps_repo()
        if embedded and os.path.abspath(cfg.bkps_repo_dir) == os.path.abspath(embedded):
            print_info(
                f"bkps_ui is already inside the source tree at {cfg.bkps_repo_dir} "
                "— skipping git clone"
            )
        else:
            print_info(
                f"Using existing BKPS source checkout at {cfg.bkps_repo_dir} "
                "— skipping git clone"
            )
    else:
        print_info("Repository directory already exists, skip cloning ...")

    # LOCAL-FILE OVERRIDE (TEMP WORKAROUND) — grep-remove `local_override_`
    _apply_local_gradle_zip_override(cfg)
    _apply_linux_spdm_wrapper_malloc_link(cfg.bkps_repo_dir)

    print_step(4, "Building selected BKPS artifacts...")
    _ensure_agilex5_spdm_wrapper(cfg)

    # ------------------------------------------------------------------ Step 5
    sid = print_step(5, f"Copying/updating files to {cfg.bkps_dir}...")
    repo_root = cfg.bkps_repo_dir
    bkps_src = os.path.join(repo_root, "bkps")
    cfg.bkps_jar_path = _require_bkps_executable_jar(
        [
            os.path.join(repo_root, "out", "bkps*.jar"),
            os.path.join(repo_root, "out_windows", "bkps", "bkps*.jar"),
            os.path.join(bkps_src, "build", "libs", "bkps*.jar"),
        ],
    )
    cfg.bkps_sql_path = _require_sql_schema(bkps_src, repo_root)
    wrapper_candidates = _find_libspdm_wrapper_candidates(bkps_src)
    platform_ext = ".dll" if sys.platform.startswith("win") else ".so"
    wrapper_candidates = [
        path for path in wrapper_candidates if path.lower().endswith(platform_ext)
    ]
    if not wrapper_candidates:
        raise RuntimeError(
            f"libspdm wrapper {platform_ext} was not produced by the repository build"
        )
    cfg.libspdm_wrapper_path = max(wrapper_candidates, key=os.path.getmtime)
    admin_candidates = [
        os.path.join(repo_root, "admintools", "bkps", "bkps"),
        os.path.join(repo_root, "admintools", "bkps"),
    ]
    cfg.bkps_admin_tools_dir = next(
        (path for path in admin_candidates if os.path.isdir(path)), ""
    )
    if not cfg.bkps_admin_tools_dir:
        raise RuntimeError("BKPS admin-tools directory was not found in the repository")
    install_from_files(cfg, parent_step=sid)

    print_success("Build complete!")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# ── Internal helpers ─────────────────────────────────────────────────────────

def _extract_zip(zip_path: str, dest_dir: str, password: str = "") -> None:
    """Extract a ZIP with native unzip when available, otherwise Python zipfile.

    Args:
        zip_path: Absolute path to the ZIP archive.
        dest_dir: Directory to extract into (created if absent).
        password: Optional ZIP encryption password.
    """
    import subprocess
    import zipfile

    os.makedirs(dest_dir, exist_ok=True)

    if shutil.which("unzip"):
        cmd = ["unzip", "-o", zip_path, "-d", dest_dir]
        if password:
            cmd = ["unzip", "-o", "-P", password, zip_path, "-d", dest_dir]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode not in (0, 1):  # unzip exits 1 for warnings (harmless)
            # If native unzip failed, fall through to zipfile
            print_warning(f"unzip exited {result.returncode}, retrying with Python zipfile...")
        else:
            return

    # Fallback: Python's zipfile module
    pwd = password.encode() if password else None
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(dest_dir, pwd=pwd)
    except RuntimeError as exc:
        msg = str(exc).lower()
        if "encrypted" in msg or "password" in msg:
            print_error(
                "ZIP is encrypted but no password is configured.\n"
                "Set the password on the Config tab → Bundle Password field."
            )
        raise


def _read_gradle_jvmargs(repo_dir: str) -> str:
    """Return org.gradle.jvmargs from the project's gradle.properties, or ''."""
    for props_path in [
        os.path.join(repo_dir, "gradle.properties"),
        os.path.join(repo_dir, "bkps", "gradle.properties"),
    ]:
        if os.path.isfile(props_path):
            try:
                with open(props_path) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("org.gradle.jvmargs="):
                            return line.split("=", 1)[1].strip()
            except OSError:
                pass
    return ""


def _proxy_java_opts() -> str:
    """Return Java ``-D`` proxy flags derived from http_proxy / https_proxy."""
    from urllib.parse import urlparse

    opts = ["-Djava.net.useSystemProxies=true"]
    for scheme in ("http", "https"):
        proxy_url = (
            os.environ.get(f"{scheme}_proxy")
            or os.environ.get(f"{scheme.upper()}_PROXY", "")
        )
        if not proxy_url:
            continue
        try:
            parsed = urlparse(proxy_url)
            host = parsed.hostname
            port = parsed.port
            if host:
                opts.append(f"-D{scheme}.proxyHost={host}")
            if port:
                opts.append(f"-D{scheme}.proxyPort={port}")
            if parsed.username:
                opts.append(f"-D{scheme}.proxyUser={parsed.username}")
            if parsed.password:
                opts.append(f"-D{scheme}.proxyPassword={parsed.password}")
        except Exception:
            pass
    return " ".join(opts)


def _build_gradle_opts(repo_dir: str) -> str:
    """Compose GRADLE_OPTS from project JVM args, console mode, and proxy flags.

    The console property is set here, not only on the command line, because the
    repository's own build scripts invoke ``./gradlew`` without it. Those run on
    a PTY so that long builds stream, and a PTY makes Gradle select its rich
    console, whose cursor-movement escapes are meaningless in a log.
    """
    jvm_args   = _read_gradle_jvmargs(repo_dir)
    proxy_opts = _proxy_java_opts()
    return " ".join(filter(None, [
        jvm_args,
        "-Dorg.gradle.daemon=false",
        "-Dorg.gradle.console=plain",
        proxy_opts,
    ]))


def fetch_bkps_releases(timeout: int = 10) -> list:
    """Fetch BKPS release branch names from the GitHub API (empty list on failure).

    Args:
        timeout: HTTP request timeout in seconds.
    """
    import json
    import urllib.request

    # Derive the API URL from the repo constant to stay in sync automatically
    # (str.removeprefix / removesuffix require Python 3.9+ — use manual slicing
    # for 3.8 compatibility).
    _prefix = "https://github.com/"
    _suffix = ".git"
    repo_path = BKPS_REPO_URL
    if repo_path.startswith(_prefix):
        repo_path = repo_path[len(_prefix):]
    if repo_path.endswith(_suffix):
        repo_path = repo_path[:-len(_suffix)]
    url = f"https://api.github.com/repos/{repo_path}/branches?per_page=100"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "bkps-demo-tool",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
            if isinstance(data, list):
                releases = [
                    item["name"]
                    for item in data
                    if isinstance(item, dict)
                    and item.get("name", "").startswith("release/")
                ]
                releases.sort(reverse=True)
                names = {
                    item.get("name", "")
                    for item in data
                    if isinstance(item, dict) and item.get("name")
                }
                if "master" in names:
                    return ["master"] + releases
                return releases
    except Exception:
        pass
    return []


def _sql_has_ddl(sql_path: str) -> bool:
    """Return True if the SQL file contains a CREATE TABLE statement."""
    try:
        with open(sql_path, "r", errors="replace") as f:
            for line in f:
                if "CREATE TABLE" in line.upper():
                    return True
    except OSError:
        pass
    return False


def _require_newest_artifact(label: str, patterns: list[str]) -> str:
    """Return the newest file matching known repository output locations."""
    candidates: list[str] = []
    for pattern in patterns:
        candidates.extend(glob.glob(pattern, recursive=True))
    candidates = [path for path in dict.fromkeys(candidates) if os.path.isfile(path)]
    if not candidates:
        raise RuntimeError(f"{label} was not produced; searched: {', '.join(patterns)}")
    selected = max(candidates, key=os.path.getmtime)
    print_success(f"{label} located: {selected}")
    return selected


def _require_bkps_executable_jar(patterns: list[str]) -> str:
    """Locate the executable BKPS JAR and never select the ``-plain`` JAR."""
    candidates: list[str] = []
    for pattern in patterns:
        candidates.extend(glob.glob(pattern, recursive=True))
    candidates = [
        path for path in dict.fromkeys(candidates)
        if os.path.isfile(path) and not path.lower().endswith("-plain.jar")
    ]
    if not candidates:
        raise RuntimeError(
            "Executable BKPS JAR was not produced; searched: "
            + ", ".join(patterns)
        )
    selected = max(candidates, key=os.path.getmtime)
    print_success(f"BKPS executable JAR located: {selected}")
    return selected


def _sql_schema_patterns(bkps_src: str, repo_root: str) -> list[str]:
    """Return the repository locations that may hold the generated schema."""
    return [
        os.path.join(repo_root, "out", "bkps*.sql"),
        os.path.join(repo_root, "out_windows", "bkps", "bkps*.sql"),
        os.path.join(bkps_src, "*.sql"),
        os.path.join(bkps_src, "**", "bkps*.sql"),
    ]


def _find_sql_schema(bkps_src: str, repo_root: str) -> str:
    """Return the newest schema file containing DDL, or "" when none exists."""
    candidates: list[str] = []
    for pattern in _sql_schema_patterns(bkps_src, repo_root):
        candidates.extend(glob.glob(pattern, recursive=True))
    valid = [
        path for path in dict.fromkeys(candidates)
        if os.path.isfile(path) and _sql_has_ddl(path)
    ]
    return max(valid, key=os.path.getmtime) if valid else ""


def _require_sql_schema(bkps_src: str, repo_root: str) -> str:
    """Locate the Gradle-generated BKPS SQL schema and reject empty headers."""
    selected = _find_sql_schema(bkps_src, repo_root)
    if not selected:
        raise RuntimeError(
            "BKPS SQL schema with CREATE TABLE statements was not produced; "
            f"searched: {', '.join(_sql_schema_patterns(bkps_src, repo_root))}"
        )
    print_success(f"BKPS SQL schema located: {selected}")
    return selected


def _project_gradle_executable(repo_root: str) -> str:
    """Return the repository Gradle wrapper for the current platform."""
    wrapper_name = "gradlew.bat" if sys.platform.startswith("win") else "gradlew"
    wrapper = os.path.abspath(os.path.join(repo_root, wrapper_name))
    if os.path.isfile(wrapper):
        return wrapper
    installed = shutil.which("gradle") or ""
    return os.path.abspath(installed) if installed else ""


def _build_bkps_jar_and_sql(cfg: Config) -> None:
    """Build the JAR and SQL with build files owned by the cloned repository."""
    repo_root = os.path.abspath(cfg.bkps_repo_dir)
    bkps_src = os.path.join(repo_root, "bkps")
    if not os.path.isdir(bkps_src):
        raise RuntimeError(f"BKPS source directory not found: {bkps_src}")
    gradle_exe = _project_gradle_executable(repo_root)
    if not gradle_exe:
        raise RuntimeError(
            f"Repository Gradle wrapper not found under {repo_root} and Gradle is not in PATH"
        )

    gradle_args = [
        "--no-daemon", "--console=plain", "-Pprod", "-Paws",
        "clean", "bootJar", "liquibaseGenerateSql",
    ]
    version = (getattr(cfg, "bkps_version", "") or "").strip()
    if version:
        gradle_args.extend([f"-Pversion={version}", f"-Dversion={version}"])
    gradle_env = {
        "KEYSTORE_DUMMY_ALIAS": "dummy",
        "GRADLE_OPTS": _build_gradle_opts(repo_root),
    }
    print_info(f"Building BKPS JAR and SQL with repository wrapper: {gradle_exe}")
    result = stream([gradle_exe] + gradle_args, cwd=bkps_src, env=gradle_env)
    if result != 0:
        raise RuntimeError(f"Repository Gradle build failed with exit code {result}")

    _require_bkps_executable_jar(
        [os.path.join(bkps_src, "build", "libs", "bkps*.jar")],
    )
    _require_sql_schema(bkps_src, repo_root)


def _ensure_bkps_sql_schema(cfg: Config) -> None:
    """Generate the Liquibase schema when the repository build does not.

    ``bkps/build.gradle`` registers ``liquibaseGenerateSql`` only under
    ``-Pprod`` or ``-Paws``, and the repository's own full-build Gradle call
    passes neither, so a full build yields no schema. Selected builds and the
    patched Windows script already generate it, so this runs only when nothing
    valid exists yet.
    """
    repo_root = os.path.abspath(cfg.bkps_repo_dir)
    bkps_src = os.path.join(repo_root, "bkps")
    if _find_sql_schema(bkps_src, repo_root):
        return

    gradle_exe = _project_gradle_executable(repo_root)
    if not gradle_exe:
        raise RuntimeError(
            f"Repository Gradle wrapper not found under {repo_root} and Gradle "
            "is not in PATH, so the BKPS SQL schema cannot be generated"
        )
    gradle_args = [
        "--no-daemon", "--console=plain", "-Pprod", "-Paws",
        "liquibaseGenerateSql",
    ]
    version = (getattr(cfg, "bkps_version", "") or "").strip()
    if version:
        gradle_args.extend([f"-Pversion={version}", f"-Dversion={version}"])
    print_info(
        "The repository build produced no SQL schema; generating it with "
        "Liquibase..."
    )
    result = stream(
        [gradle_exe] + gradle_args,
        cwd=bkps_src,
        env={
            "KEYSTORE_DUMMY_ALIAS": "dummy",
            "GRADLE_OPTS": _build_gradle_opts(repo_root),
        },
    )
    if result != 0:
        raise RuntimeError(
            f"Liquibase SQL generation failed with exit code {result}"
        )


def _find_libspdm_wrapper_candidates(bkps_src: str) -> list[str]:
    """Locate built libspdm wrapper shared libraries under the BKPS source tree.

    Args:
        bkps_src: Path to the ``bkps/`` sub-module inside the repo clone.
    """
    repo_root = os.path.dirname(bkps_src)
    patterns = [
        os.path.join(bkps_src, "build", "**", "libspdm_wrapper*.so"),
        os.path.join(bkps_src, "**", "libspdm_wrapper*.so"),
        os.path.join(repo_root, "spdm_wrapper", "build", "**", "libspdm_wrapper*.so"),
        os.path.join(repo_root, "out", "spdm_wrapper", "**", "libspdm_wrapper*.so"),
        os.path.join(repo_root, "out_windows", "spdm_wrapper", "**", "libspdm_wrapper*.so"),
        # Windows DLL equivalents
        os.path.join(bkps_src, "build", "**", "*spdm_wrapper*.dll"),
        os.path.join(bkps_src, "**", "*spdm_wrapper*.dll"),
        os.path.join(repo_root, "spdm_wrapper", "build", "**", "*spdm_wrapper*.dll"),
        os.path.join(repo_root, "out", "spdm_wrapper", "**", "*spdm_wrapper*.dll"),
        os.path.join(repo_root, "out_windows", "spdm_wrapper", "**", "*spdm_wrapper*.dll"),
    ]
    candidates: list[str] = []
    for pattern in patterns:
        candidates.extend(glob.glob(pattern, recursive=True))
    # Preserve order while removing duplicates.
    return list(dict.fromkeys(candidates))


def _ensure_agilex5_spdm_wrapper(cfg: Config) -> None:
    """Build repository-owned BKPS artifacts using the platform flow."""

    print_info("Building BKPS JAR, SQL schema, and SPDM wrapper...")
    repo_root = cfg.bkps_repo_dir

    if sys.platform.startswith("win"):
        if not build_native_dependencies(cfg, repo_dir=repo_root, force=True):
            raise RuntimeError(
                "Repository Windows build failed. See log above for details."
            )
        wrapper_candidates = [
            path for path in _find_libspdm_wrapper_candidates(
                os.path.join(repo_root, "bkps")
            )
            if path.lower().endswith(".dll")
        ]
        if not wrapper_candidates:
            raise RuntimeError(
                "The repository Windows flow completed without producing "
                "libspdm_wrapper.dll"
            )
        _validate_spdm_wrapper(
            max(wrapper_candidates, key=os.path.getmtime)
        )
        _ensure_bkps_sql_schema(cfg)
        return

    deps_root = os.path.join(repo_root, "dependencies")
    if os.path.isdir(deps_root):
        print_info(f"  Removing existing dependencies directory: {deps_root}")
        shutil.rmtree(deps_root, ignore_errors=True)

    if not build_native_dependencies(cfg, repo_dir=repo_root, force=True):
        raise RuntimeError(
            "Native dependency build failed. See log above for details."
        )
    wrapper_candidates = [
        path for path in _find_libspdm_wrapper_candidates(
            os.path.join(repo_root, "bkps")
        )
        if path.lower().endswith(".so")
    ]
    if not wrapper_candidates:
        raise RuntimeError(
            "The repository Linux flow completed without producing "
            "libspdm_wrapper.so"
        )
    _validate_spdm_wrapper(max(wrapper_candidates, key=os.path.getmtime))
    _ensure_bkps_sql_schema(cfg)


def _validate_spdm_wrapper(wrapper_path: str) -> None:
    """Load the generated wrapper and verify the BKPS-facing exports.

    A wrapper that exists but cannot be loaded, or that lost an export, fails
    later inside the BKPS JVM with a far less obvious error, so both platforms
    are checked here.
    """
    import ctypes

    on_windows = sys.platform.startswith("win")
    platform_name = "Windows" if on_windows else "Linux"
    loader = ctypes.WinDLL if on_windows else ctypes.CDLL
    try:
        library = loader(os.path.abspath(wrapper_path))
    except (AttributeError, OSError) as exc:
        raise RuntimeError(
            f"{platform_name} produced {wrapper_path}, but the library could "
            f"not be loaded: {exc}"
        ) from exc
    required_exports = (
        "set_callbacks",
        "libspdm_get_context_size_w",
        "libspdm_prepare_context_w",
        "libspdm_send_receive_data_w",
    )
    missing = [name for name in required_exports if not hasattr(library, name)]
    if missing:
        raise RuntimeError(
            f"{platform_name} SPDM wrapper is missing required exports: "
            + ", ".join(missing)
        )
    context_size = library.libspdm_get_context_size_w
    context_size.restype = ctypes.c_size_t
    if context_size() <= 0:
        raise RuntimeError(
            f"{platform_name} SPDM wrapper returned an invalid context size"
        )
    print_success(f"{platform_name} SPDM wrapper validated: {wrapper_path}")


def _install_libspdm_wrapper(cfg: Config, bkps_src: str) -> None:
    """Copy the built libspdm wrapper into cfg.bkps_dir (and /usr/lib on Linux).

    Args:
        bkps_src: Path to the ``bkps/`` sub-module whose build output is searched.
    """
    # User supplied an explicit path — nothing to install.
    if cfg.libspdm_wrapper_path and os.path.isfile(cfg.libspdm_wrapper_path):
        print_info(f"  libspdm wrapper already configured: {cfg.libspdm_wrapper_path}")
        return

    candidates = _find_libspdm_wrapper_candidates(bkps_src)
    if not candidates:
        print_warning("  libspdm_wrapper not found in build output — skipping install")
        return

    src_lib = candidates[0]
    dest_lib = os.path.join(cfg.bkps_dir, os.path.basename(src_lib))

    if not os.path.isfile(dest_lib):
        print_info(f"  Copying libspdm wrapper to BKPS directory...")
        shutil.copy2(src_lib, dest_lib)
        print_success(f"  libspdm wrapper copied to: {dest_lib}")
    else:
        print_info(f"  libspdm wrapper already in BKPS directory: {dest_lib}")

    # Update cfg so all subsequent steps (YAML config, server setup) use this path.
    cfg.libspdm_wrapper_path = dest_lib


def install_from_files(cfg: Config, parent_step=None) -> None:
    """Copy a pre-built BKPS JAR, SQL schema, admin-tools, and libspdm wrapper into cfg.bkps_dir.

    Args:
        parent_step: When set, print inner steps as parent.1, parent.2, ...
    """
    print_header("Installing BKPS from Pre-built Files")

    if not cfg.bkps_jar_path:
        print_error("BKPS_JAR_PATH is not configured.")
        raise ValueError("BKPS_JAR_PATH is not configured.")
    if not cfg.bkps_sql_path:
        print_error("BKPS_SQL_PATH is not configured.")
        raise ValueError("BKPS_SQL_PATH is not configured.")
    if not cfg.libspdm_wrapper_path:
        print_error("LIBSPDM_WRAPPER_PATH is not configured.")
        raise ValueError("LIBSPDM_WRAPPER_PATH is not configured.")
    if not cfg.bkps_admin_tools_dir:
        print_error("BKPS_ADMIN_TOOLS_DIR is not configured.")
        raise ValueError("BKPS_ADMIN_TOOLS_DIR is not configured.")

    if not os.path.isfile(cfg.bkps_jar_path):
        print_error(f"BKPS JAR not found: {cfg.bkps_jar_path}")
        raise FileNotFoundError(f"BKPS JAR not found: {cfg.bkps_jar_path}")
    if not os.path.isfile(cfg.bkps_sql_path):
        print_error(f"BKPS SQL not found: {cfg.bkps_sql_path}")
        raise FileNotFoundError(f"BKPS SQL not found: {cfg.bkps_sql_path}")
    if not os.path.isfile(cfg.libspdm_wrapper_path):
        print_error(f"LIBSPDM_WRAPPER_PATH not found: {cfg.libspdm_wrapper_path}")
        raise FileNotFoundError(f"LIBSPDM_WRAPPER_PATH not found: {cfg.libspdm_wrapper_path}")
    if not os.path.isdir(cfg.bkps_admin_tools_dir):
        print_error(f"BKPS_ADMIN_TOOLS_DIR not found or not a directory: {cfg.bkps_admin_tools_dir}")
        raise FileNotFoundError(f"BKPS_ADMIN_TOOLS_DIR not found or not a directory: {cfg.bkps_admin_tools_dir}")

    os.makedirs(cfg.bkps_dir, exist_ok=True)
    for sub in ["admin-tools", "config", "logs"]:
        os.makedirs(os.path.join(cfg.bkps_dir, sub), exist_ok=True)

    print_step(1, "Copying JAR...", parent=parent_step)
    dest_jar = os.path.join(cfg.bkps_dir, os.path.basename(cfg.bkps_jar_path))
    shutil.copy2(cfg.bkps_jar_path, dest_jar)
    print_success(f"JAR copied: {os.path.basename(dest_jar)}")

    print_step(2, "Copying SQL schema...", parent=parent_step)
    dest_sql = os.path.join(cfg.bkps_dir, os.path.basename(cfg.bkps_sql_path))
    shutil.copy2(cfg.bkps_sql_path, dest_sql)
    print_success(f"SQL copied: {os.path.basename(dest_sql)}")

    print_step(3, "Copying libspdm wrapper...", parent=parent_step)
    dest_lib = os.path.join(cfg.bkps_dir, os.path.basename(cfg.libspdm_wrapper_path))
    shutil.copy2(cfg.libspdm_wrapper_path, dest_lib)
    cfg.libspdm_wrapper_path = dest_lib
    print_success(f"libspdm wrapper copied: {os.path.basename(dest_lib)}")

    print_step(4, "Installing admin-tools...", parent=parent_step)
    admin_dest = os.path.join(cfg.bkps_dir, "admin-tools")
    admin_src = getattr(cfg, "bkps_admin_tools_dir", "").strip()

    if admin_src and os.path.isdir(admin_src):
        # User supplied the admin-tools directory directly.
        shutil.copytree(admin_src, admin_dest, dirs_exist_ok=True)
        print_success(f"admin-tools copied from: {admin_src}")

    print_success("Pre-built files installed successfully.")


def install_bundle_zip(cfg: Config) -> None:
    """Extract a pre-built bundle ZIP into cfg.bkps_dir, including nested archives."""
    print_header("Installing Bundle from ZIP")
    if not os.path.isfile(cfg.bundle_zip):
        print_error(f"ZIP file not found: {cfg.bundle_zip}")
        raise FileNotFoundError(cfg.bundle_zip)

    os.makedirs(cfg.bkps_dir, exist_ok=True)

    marker_file = os.path.join(cfg.bkps_dir, ".bundle_extracted")

    print_step(1, f"Extracting {os.path.basename(cfg.bundle_zip)} → {cfg.bkps_dir}")
    _extract_zip(cfg.bundle_zip, cfg.bkps_dir, cfg.bundle_zip_password)
    print_success("Extraction complete")
    with open(marker_file, "w", encoding="utf-8") as f:
        f.write("bundle extracted\n")

    # Extract nested ZIPs recursively (some bundles contain a second-level ZIP)
    print_step(2, "Extracting nested ZIP files (if present)...")
    max_passes = 5
    extracted_nested = 0
    src_zip_abs = os.path.abspath(cfg.bundle_zip)

    for _pass in range(1, max_passes + 1):
        nested_zips = []
        for z in glob.glob(os.path.join(cfg.bkps_dir, "**", "*.zip"), recursive=True):
            if os.path.abspath(z) == src_zip_abs:
                continue
            nested_zips.append(z)

        if not nested_zips:
            if extracted_nested == 0:
                print_info("  No nested ZIP files found.")
            else:
                print_success(f"Nested ZIP extraction complete ({extracted_nested} extracted).")
            break

        print_info(f"  Pass {_pass}: found {len(nested_zips)} nested ZIP file(s)")
        for nz in sorted(nested_zips):
            target_dir = os.path.splitext(nz)[0]
            if os.path.isdir(target_dir) and os.listdir(target_dir):
                target_dir = os.path.dirname(nz)
            os.makedirs(target_dir, exist_ok=True)

            print_info(f"    Extracting {os.path.basename(nz)} → {target_dir}")
            _extract_zip(nz, target_dir, cfg.bundle_zip_password)

            extracted_nested += 1
            try:
                os.remove(nz)
            except OSError:
                pass
    else:
        print_warning("Reached nested ZIP extraction pass limit; continuing with discovered files.")

    # Flatten single-wrapper directories repeatedly
    print_step(3, "Normalizing directory structure...")
    for _ in range(4):
        items = os.listdir(cfg.bkps_dir)
        files = [x for x in items if os.path.isfile(os.path.join(cfg.bkps_dir, x))]
        dirs = [x for x in items if os.path.isdir(os.path.join(cfg.bkps_dir, x))]
        if len(dirs) == 1 and not files:
            wrapper = os.path.join(cfg.bkps_dir, dirs[0])
            for name in os.listdir(wrapper):
                src = os.path.join(wrapper, name)
                dst = os.path.join(cfg.bkps_dir, name)
                if os.path.exists(dst):
                    continue
                shutil.move(src, dst)
            os.rmdir(wrapper)
            print_info(f"  Flattened wrapper directory: {dirs[0]}")
            continue
        break

    # Match source-flow directory layout
    print_step(4, "Creating BKPS directory structure...")
    for sub in ["admin-tools", "config", "keys/bkps_ssl_cert", "keys/tsci_cert", "libs-ext", "logs"]:
        os.makedirs(os.path.join(cfg.bkps_dir, sub), exist_ok=True)
    print_success("Directory structure ready")

    # Promote key artifacts from nested extraction locations to bkps_dir root
    print_step(5, "Finalizing bundle artifacts...")

    def _depth(path: str) -> int:
        rel = os.path.relpath(path, cfg.bkps_dir)
        return rel.count(os.sep)

    jar_candidates = glob.glob(os.path.join(cfg.bkps_dir, "**", "bkps*.jar"), recursive=True)
    jar_candidates = sorted({os.path.abspath(p) for p in jar_candidates}, key=lambda p: (_depth(p), p))
    if jar_candidates:
        chosen_jar = jar_candidates[0]
        dest_jar = os.path.join(cfg.bkps_dir, os.path.basename(chosen_jar))
        if os.path.abspath(chosen_jar) != os.path.abspath(dest_jar):
            shutil.copy2(chosen_jar, dest_jar)
        print_success(f"JAR ready: {os.path.basename(dest_jar)}")
    else:
        print_warning("No bkps*.jar found after extraction")

    sql_candidates = glob.glob(os.path.join(cfg.bkps_dir, "**", "bkps*.sql"), recursive=True)
    sql_candidates = sorted({os.path.abspath(p) for p in sql_candidates}, key=lambda p: (_depth(p), p))
    chosen_sql = ""
    for candidate in sql_candidates:
        if _sql_has_ddl(candidate):
            chosen_sql = candidate
            break
    if chosen_sql:
        dest_sql = os.path.join(cfg.bkps_dir, os.path.basename(chosen_sql))
        if os.path.abspath(chosen_sql) != os.path.abspath(dest_sql):
            shutil.copy2(chosen_sql, dest_sql)
        print_success(f"SQL schema ready: {os.path.basename(dest_sql)}")
    else:
        print_warning("No SQL schema with DDL found; server-side Liquibase may be required")

    admin_dest = os.path.join(cfg.bkps_dir, "admin-tools")
    if not os.path.isfile(os.path.join(admin_dest, "runner.py")):
        admin_runner_candidates = glob.glob(os.path.join(cfg.bkps_dir, "**", "runner.py"), recursive=True)
        admin_runner_candidates = sorted(
            {
                os.path.abspath(p)
                for p in admin_runner_candidates
                if "admin" in p.lower() or "bkps" in p.lower()
            },
            key=lambda p: (_depth(p), p)
        )
        if admin_runner_candidates:
            src_admin = os.path.dirname(admin_runner_candidates[0])
            if os.path.abspath(src_admin) != os.path.abspath(admin_dest):
                shutil.copytree(src_admin, admin_dest, dirs_exist_ok=True)

    if os.path.isfile(os.path.join(admin_dest, "runner.py")):
        print_success("Admin tools ready: runner.py found")
    else:
        print_warning("Admin tools runner.py not found; verify bundle content")

    print_success("Bundle installed successfully.")
