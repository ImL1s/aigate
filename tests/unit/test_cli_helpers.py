"""Tests for CLI helper functions."""

from aigate.cli import _infer_ecosystem, _parse_lockfile, _strip_version_prefix


class TestInferEcosystem:
    def test_requirements_txt(self):
        assert _infer_ecosystem("requirements.txt") == "pypi"

    def test_package_lock(self):
        assert _infer_ecosystem("package-lock.json") == "npm"

    def test_yarn_lock(self):
        assert _infer_ecosystem("yarn.lock") == "npm"

    def test_pnpm_lock(self):
        assert _infer_ecosystem("pnpm-lock.yaml") == "npm"

    def test_pubspec_lock(self):
        assert _infer_ecosystem("pubspec.lock") == "pub"

    def test_unknown_defaults_pypi(self):
        assert _infer_ecosystem("something.lock") == "pypi"

    def test_full_path(self):
        assert _infer_ecosystem("/home/user/project/package-lock.json") == "npm"


class TestStripVersionPrefix:
    def test_with_prefix(self):
        assert _strip_version_prefix("litellm-1.82.7/setup.py") == "setup.py"

    def test_nested_path(self):
        result = _strip_version_prefix("pkg-1.0/src/main.py")
        assert result == "src/main.py"

    def test_no_prefix(self):
        assert _strip_version_prefix("setup.py") == "setup.py"


class TestParseLockfile:
    def test_requirements_txt(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.31.0\nflask>=2.0\nnumpy\n# comment\n-r other.txt\n")
        result = _parse_lockfile(str(f))
        assert ("requests", "2.31.0") in result
        assert ("flask", "") in result
        assert ("numpy", "") in result
        # Should skip comment and -r
        assert len(result) == 3

    def test_empty_file(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("")
        assert _parse_lockfile(str(f)) == []

    def test_uv_lock(self, tmp_path):
        f = tmp_path / "uv.lock"
        f.write_text(
            """
version = 1

[[package]]
name = "httpx"
version = "0.27.2"

[[package]]
name = "pydantic"
version = "2.9.0"
""".strip()
        )

        result = _parse_lockfile(str(f))

        assert ("httpx", "0.27.2") in result
        assert ("pydantic", "2.9.0") in result

    def test_pnpm_lock(self, tmp_path):
        f = tmp_path / "pnpm-lock.yaml"
        f.write_text(
            """
lockfileVersion: '9.0'
packages:
  express@4.19.2:
    resolution: {integrity: sha512-abc}
  '@types/node@20.11.30':
    resolution: {integrity: sha512-def}
""".strip()
        )

        result = _parse_lockfile(str(f))

        assert ("express", "4.19.2") in result
        assert ("@types/node", "20.11.30") in result

    def test_yarn_lock(self, tmp_path):
        f = tmp_path / "yarn.lock"
        f.write_text(
            """
"react@^18.2.0":
  version "18.3.1"
  resolved "https://registry.yarnpkg.com/react/-/react-18.3.1.tgz"

"@types/node@^20.0.0":
  version "20.16.10"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-20.16.10.tgz"
""".strip()
        )

        result = _parse_lockfile(str(f))

        assert ("react", "18.3.1") in result
        assert ("@types/node", "20.16.10") in result
