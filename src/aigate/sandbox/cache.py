"""Sandbox output cache — no-op stub (Phase 2 lands real cache, PRD §3.8)."""

from __future__ import annotations

from .types import DynamicTrace


def get(cache_key: str) -> DynamicTrace | None:  # noqa: ARG001
    return None


def put(cache_key: str, trace: DynamicTrace) -> None:  # noqa: ARG001
    return None
