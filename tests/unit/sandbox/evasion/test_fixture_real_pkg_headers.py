"""R9 mitigation: every detector has ≥1 real-pkg fixture with Source header."""

from pathlib import Path

FIXTURE_ROOT = Path(__file__).parents[3] / "fixtures" / "evasion"


def test_every_detector_has_real_pkg_fixture_with_source_header():
    detector_dirs = [d for d in FIXTURE_ROOT.iterdir() if d.is_dir()]
    assert len(detector_dirs) == 7, (
        f"expected 7 detector dirs, got {len(detector_dirs)}: {[d.name for d in detector_dirs]}"
    )
    for det_dir in detector_dirs:
        real_pkg_files = [f for f in det_dir.iterdir() if "real" in f.name.lower()]
        assert real_pkg_files, (
            f"{det_dir.name}: no real-pkg fixture (expected at least one neg_real_*.* file)"
        )
        real_path = real_pkg_files[0]
        first_line = real_path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
        prefixes = ("# Source:", "// Source:", "/* Source:")
        assert first_line.startswith(prefixes), (
            f"{det_dir.name}/{real_path.name}: first line must start with "
            f"'# Source: <path>@<sha>' header, got: {first_line!r}"
        )
