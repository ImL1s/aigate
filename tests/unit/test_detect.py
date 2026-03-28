"""Tests for AI tool auto-detection."""

from __future__ import annotations

from aigate.detect import (
    KNOWN_BACKENDS,
    KNOWN_HOOK_TOOLS,
    DetectedBackend,
    detect_backends,
    detect_hooks,
    generate_config_yaml,
)


def test_detect_claude_when_available(monkeypatch):
    monkeypatch.setattr(
        "aigate.detect.shutil.which",
        lambda name: f"/usr/bin/{name}" if name == "claude" else None,
    )
    backends = detect_backends()
    names = [b.name for b in backends]
    assert "claude" in names


def test_detect_nothing_when_nothing_installed(monkeypatch):
    monkeypatch.setattr("aigate.detect.shutil.which", lambda name: None)
    backends = detect_backends()
    assert len(backends) == 0


def test_detect_multiple_tools(monkeypatch):
    installed = {"claude", "gemini", "codex"}
    monkeypatch.setattr(
        "aigate.detect.shutil.which",
        lambda name: f"/usr/bin/{name}" if name in installed else None,
    )
    backends = detect_backends()
    names = {b.name for b in backends}
    assert names == {"claude", "gemini", "codex"}


def test_detected_backend_has_install_hint():
    for info in KNOWN_BACKENDS:
        assert info.install_hint  # Every backend must have install instructions


def test_detected_backend_fields():
    b = DetectedBackend(
        name="test",
        backend="test",
        available=True,
        binary_path="/usr/bin/test",
        install_hint="install it",
        default_model_id="model-1",
        default_weight=0.9,
    )
    assert b.name == "test"
    assert b.available is True
    assert b.binary_path == "/usr/bin/test"


def test_detect_hooks_finds_installed_tools(monkeypatch):
    installed = {"claude", "codex"}
    monkeypatch.setattr(
        "aigate.detect.shutil.which",
        lambda name: f"/usr/bin/{name}" if name in installed else None,
    )
    hooks = detect_hooks()
    tool_names = {h.tool for h in hooks}
    assert "claude" in tool_names
    assert "codex" in tool_names
    # File-based tools are always included
    assert "cline" in tool_names
    assert "opencode" in tool_names


def test_detect_hooks_none_installed(monkeypatch):
    monkeypatch.setattr("aigate.detect.shutil.which", lambda name: None)
    hooks = detect_hooks()
    # File-based tools (cline, opencode) are always reported as available
    tool_names = {h.tool for h in hooks}
    assert tool_names == {"cline", "opencode"}
    for h in hooks:
        assert h.note == "file-based tool (no CLI binary needed)"
        assert h.binary_path is None


def test_known_hook_tools_includes_expected():
    expected = {"claude", "gemini", "codex", "cursor", "windsurf", "aider", "opencode", "cline"}
    assert set(KNOWN_HOOK_TOOLS) == expected


def test_known_backends_includes_expected():
    names = {b.name for b in KNOWN_BACKENDS}
    assert names == {"claude", "gemini", "codex", "ollama"}


def test_generate_config_from_detected(monkeypatch):
    installed = {"claude", "gemini"}
    monkeypatch.setattr(
        "aigate.detect.shutil.which",
        lambda name: f"/usr/bin/{name}" if name in installed else None,
    )
    yaml_str = generate_config_yaml(detect_backends())
    assert "claude" in yaml_str
    assert "gemini" in yaml_str
    assert "codex" not in yaml_str
    # dual-model strategy comment
    assert "dual-model" in yaml_str


def test_generate_config_no_backends():
    yaml_str = generate_config_yaml([])
    assert "No AI backends detected" in yaml_str
    assert "prefilter-only" in yaml_str


def test_generate_config_single_backend(monkeypatch):
    monkeypatch.setattr(
        "aigate.detect.shutil.which",
        lambda name: f"/usr/bin/{name}" if name == "claude" else None,
    )
    yaml_str = generate_config_yaml(detect_backends())
    assert "single-model" in yaml_str


def test_generate_config_full_consensus(monkeypatch):
    installed = {"claude", "gemini", "codex", "ollama"}
    monkeypatch.setattr(
        "aigate.detect.shutil.which",
        lambda name: f"/usr/bin/{name}" if name in installed else None,
    )
    yaml_str = generate_config_yaml(detect_backends())
    assert "full multi-model consensus" in yaml_str


def test_generate_config_has_thresholds(monkeypatch):
    monkeypatch.setattr(
        "aigate.detect.shutil.which",
        lambda name: f"/usr/bin/{name}" if name == "claude" else None,
    )
    yaml_str = generate_config_yaml(detect_backends())
    assert "thresholds:" in yaml_str
    assert "malicious: 0.6" in yaml_str


def test_generate_config_has_ecosystems(monkeypatch):
    monkeypatch.setattr(
        "aigate.detect.shutil.which",
        lambda name: f"/usr/bin/{name}" if name == "claude" else None,
    )
    yaml_str = generate_config_yaml(detect_backends())
    assert "ecosystems:" in yaml_str
    assert "- pypi" in yaml_str
    assert "- npm" in yaml_str


def test_generate_config_has_enrichment():
    yaml_str = generate_config_yaml([])
    assert "enrichment:" in yaml_str
    assert "osv:" in yaml_str


def test_detect_ollama(monkeypatch):
    monkeypatch.setattr(
        "aigate.detect.shutil.which",
        lambda name: "/usr/local/bin/ollama" if name == "ollama" else None,
    )
    backends = detect_backends()
    assert len(backends) == 1
    assert backends[0].name == "ollama"
    assert backends[0].default_weight == 0.8
    assert backends[0].binary_path == "/usr/local/bin/ollama"
