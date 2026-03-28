"""Tests for the npm install hook — package spec parsing and command routing."""

import pytest

from aigate.hooks import npm_hook
from aigate.hooks.npm_hook import (
    _extract_packages,
    _install_commands_for,
    _parse_npm_spec,
)


class TestParseNpmSpec:
    """Test _parse_npm_spec for various npm package specifiers."""

    def test_plain_name(self):
        assert _parse_npm_spec("express") == ("express", None)

    def test_name_with_version(self):
        assert _parse_npm_spec("express@4.18.2") == ("express", "4.18.2")

    def test_name_with_range(self):
        assert _parse_npm_spec("lodash@^4.17.0") == ("lodash", "^4.17.0")

    def test_name_with_tilde(self):
        assert _parse_npm_spec("chalk@~5.0.0") == ("chalk", "~5.0.0")

    def test_name_with_latest_tag(self):
        assert _parse_npm_spec("react@latest") == ("react", "latest")

    def test_scoped_package(self):
        assert _parse_npm_spec("@angular/core") == ("@angular/core", None)

    def test_scoped_package_with_version(self):
        assert _parse_npm_spec("@angular/core@17.0.0") == ("@angular/core", "17.0.0")

    def test_scoped_package_with_range(self):
        assert _parse_npm_spec("@types/node@^20") == ("@types/node", "^20")

    def test_dotted_name(self):
        assert _parse_npm_spec("socket.io") == ("socket.io", None)

    def test_dotted_name_with_version(self):
        assert _parse_npm_spec("socket.io@4.7.0") == ("socket.io", "4.7.0")

    def test_hyphenated_name(self):
        assert _parse_npm_spec("my-package") == ("my-package", None)

    def test_underscore_name(self):
        assert _parse_npm_spec("my_package") == ("my_package", None)


class TestExtractPackages:
    """Test _extract_packages for different package managers."""

    def test_npm_single_package(self):
        args = ["install", "express"]
        result = _extract_packages(args, "npm")
        assert result == [("express", None)]

    def test_npm_multiple_packages(self):
        args = ["install", "express", "lodash@4.17.21", "@types/node@20"]
        result = _extract_packages(args, "npm")
        assert result == [
            ("express", None),
            ("lodash", "4.17.21"),
            ("@types/node", "20"),
        ]

    def test_npm_with_flags(self):
        args = ["install", "--save-dev", "typescript@5", "--save-exact"]
        result = _extract_packages(args, "npm")
        assert result == [("typescript", "5")]

    def test_npm_shorthand(self):
        args = ["i", "express"]
        result = _extract_packages(args, "npm")
        assert result == [("express", None)]

    def test_yarn_add(self):
        args = ["add", "react", "react-dom@18"]
        result = _extract_packages(args, "yarn")
        assert result == [("react", None), ("react-dom", "18")]

    def test_yarn_with_dev_flag(self):
        args = ["add", "-D", "jest@29"]
        result = _extract_packages(args, "yarn")
        assert result == [("jest", "29")]

    def test_pnpm_add(self):
        args = ["add", "vite@5"]
        result = _extract_packages(args, "pnpm")
        assert result == [("vite", "5")]

    def test_pnpm_install_shorthand(self):
        args = ["i", "zod"]
        result = _extract_packages(args, "pnpm")
        assert result == [("zod", None)]

    def test_skip_workspace_flag(self):
        args = ["install", "--workspace", "packages/app", "express"]
        result = _extract_packages(args, "npm")
        assert result == [("express", None)]

    def test_skip_registry_flag(self):
        args = ["install", "--registry", "https://my.registry.com", "express"]
        result = _extract_packages(args, "npm")
        assert result == [("express", None)]

    def test_no_packages_bare_install(self):
        """npm install with no args should return empty — just reinstalls."""
        args = ["install"]
        result = _extract_packages(args, "npm")
        assert result == []

    def test_scoped_packages_mixed(self):
        args = ["add", "@vue/cli@5", "vue@3", "@babel/core"]
        result = _extract_packages(args, "yarn")
        assert result == [
            ("@vue/cli", "5"),
            ("vue", "3"),
            ("@babel/core", None),
        ]


class TestInstallCommands:
    """Test _install_commands_for returns correct sub-commands per PM."""

    def test_npm_commands(self):
        cmds = _install_commands_for("npm")
        assert "install" in cmds
        assert "i" in cmds
        assert "add" in cmds

    def test_yarn_commands(self):
        cmds = _install_commands_for("yarn")
        assert "add" in cmds
        assert "install" in cmds

    def test_pnpm_commands(self):
        cmds = _install_commands_for("pnpm")
        assert "add" in cmds
        assert "install" in cmds
        assert "i" in cmds


def test_npm_wrapper_bypasses_with_no_aigate(monkeypatch):
    seen: dict[str, object] = {}

    monkeypatch.setattr(
        npm_hook.sys,
        "argv",
        ["aigate-npm", "npm", "install", "--no-aigate", "react"],
    )
    monkeypatch.setattr(
        npm_hook,
        "_passthrough",
        lambda pm, args: seen.update({"pm": pm, "args": args}),
    )
    monkeypatch.setattr(
        npm_hook.asyncio,
        "run",
        lambda _: pytest.fail("npm_wrapper should bypass without invoking aigate"),
    )

    npm_hook.npm_wrapper()

    assert seen == {"pm": "npm", "args": ["install", "react"]}
