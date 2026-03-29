"""Build synthetic malicious packages into real .tar.gz sdist archives.

Reads PACKAGE_FILES dicts from tests/fixtures/fake_malicious_*.py and
creates proper sdist tarballs in tests/e2e/packages/.

These packages contain the SAME code patterns as our unit test fixtures,
but packaged as real archives that pypiserver can serve and aigate can download.

SAFETY: The code inside is NEVER executed. aigate only reads source text.
The Docker test environment has no outbound network access as an extra safeguard.
"""

from __future__ import annotations

import importlib
import io
import sys
import tarfile
from pathlib import Path

# Fixture modules and their package metadata.
# Names and versions are extracted from each fixture's PACKAGE_FILES dict keys
# (e.g. "ctx-0.2.6/setup.py" → name="ctx", version="0.2.6").
FIXTURES = [
    {
        "module": "tests.fixtures.fake_malicious_crossenv",
        "name": "crossenv",
        "version": "6.1.1",
    },
    {
        "module": "tests.fixtures.fake_malicious_event_stream",
        "name": "flatmap-stream",
        "version": "0.1.1",
    },
    {
        "module": "tests.fixtures.fake_malicious_colors",
        "name": "colors",
        "version": "1.4.44",
    },
    {
        "module": "tests.fixtures.fake_malicious_ua_parser",
        "name": "ua-parser-js",
        "version": "0.7.29",
    },
    {
        "module": "tests.fixtures.fake_malicious_ctx",
        "name": "ctx",
        "version": "0.2.6",
    },
    {
        "module": "tests.fixtures.fake_malicious_torchtriton",
        "name": "torchtriton",
        "version": "2.0.0",
    },
    {
        "module": "tests.fixtures.fake_malicious_w4sp",
        "name": "typesutil",
        "version": "0.1.3",
    },
    {
        "module": "tests.fixtures.fake_malicious_litellm",
        "name": "litellm",
        "version": "1.82.7",
    },
]


def build_sdist(package_files: dict[str, str], name: str, version: str, output_dir: Path) -> Path:
    """Create a .tar.gz sdist from a PACKAGE_FILES dict."""
    filename = f"{name}-{version}.tar.gz"
    output_path = output_dir / filename

    with tarfile.open(output_path, "w:gz") as tar:
        for filepath, content in package_files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=filepath)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    return output_path


def build_all() -> list[Path]:
    """Build all synthetic malicious packages."""
    # Ensure project root is in sys.path
    project_root = Path(__file__).resolve().parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    output_dir = Path(__file__).resolve().parent / "packages"
    output_dir.mkdir(parents=True, exist_ok=True)

    built = []
    for fixture in FIXTURES:
        mod = importlib.import_module(fixture["module"])
        package_files = getattr(mod, "PACKAGE_FILES")
        path = build_sdist(package_files, fixture["name"], fixture["version"], output_dir)
        built.append(path)
        print(f"  Built: {path.name}")

    return built


if __name__ == "__main__":
    print("Building synthetic malicious packages...")
    paths = build_all()
    print(f"\n{len(paths)} packages built in tests/e2e/packages/")
