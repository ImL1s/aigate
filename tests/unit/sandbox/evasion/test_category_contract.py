"""Every Detector subclass MUST emit only its own CATEGORY constant in detect_dynamic."""

from __future__ import annotations

# Force import of every detector module so subclasses register.
from aigate.sandbox.evasion import (  # noqa: F401
    anti_debug,  # noqa: F401
    base,
    build_hooks,  # noqa: F401
    derived_exfil,  # noqa: F401
    direct_xpc,  # noqa: F401
    env_mutation,  # noqa: F401
    parser_partial_drift,  # noqa: F401
    time_bomb,  # noqa: F401
)
from aigate.sandbox.types import DynamicTrace

# Build a trace designed to potentially trigger ANY detector.
_TEST_TRACE = DynamicTrace(
    ran=True,
    runtime="test",
    events=[],
    observed=set(),
    skipped_expected=set(),
    skipped_unexpected=set(),
)


def test_all_detectors_dynamic_emissions_match_registered_categories() -> None:
    """Every detector's detect_dynamic returns a subset of {cls.CATEGORY}."""
    for cls in base.Detector.__subclasses__():
        detector = cls()
        emissions = set(detector.detect_dynamic(_TEST_TRACE))
        allowed = {cls.CATEGORY}
        assert emissions <= allowed, (
            f"{cls.__name__} emitted categories {emissions - allowed} not in {allowed}. "
            f"Every detect_dynamic MUST return [cls.CATEGORY] or []."
        )


def test_all_detectors_have_unique_category() -> None:
    """CATEGORY constants must be globally unique across all registered detectors."""
    categories = [cls.CATEGORY for cls in base.Detector.__subclasses__()]
    assert len(categories) == len(set(categories)), (
        f"Detector CATEGORY constants must be globally unique; duplicates: {categories}"
    )
