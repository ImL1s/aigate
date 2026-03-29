"""Tests for consensus engine vote aggregation."""

from unittest.mock import patch

from aigate.config import Config, ModelConfig, ThresholdConfig
from aigate.consensus import _aggregate_votes, run_consensus
from aigate.models import AnalysisLevel, ModelResult, PackageInfo, Verdict


def _result(name: str, verdict: Verdict, confidence: float = 0.9) -> ModelResult:
    return ModelResult(
        model_name=name,
        verdict=verdict,
        confidence=confidence,
        reasoning=f"{name} says {verdict.value}",
        analysis_level=AnalysisLevel.L1_QUICK,
    )


def _models(*names: str) -> list[ModelConfig]:
    return [ModelConfig(name=n, backend="claude", weight=1.0) for n in names]


def _config() -> Config:
    return Config(thresholds=ThresholdConfig(malicious=0.6, suspicious=0.5))


class TestAggregateVotes:
    def test_unanimous_safe(self):
        results = [
            _result("claude", Verdict.SAFE),
            _result("gemini", Verdict.SAFE),
        ]
        c = _aggregate_votes(results, _config(), _models("claude", "gemini"))
        assert c.final_verdict == Verdict.SAFE

    def test_unanimous_malicious(self):
        results = [
            _result("claude", Verdict.MALICIOUS),
            _result("gemini", Verdict.MALICIOUS),
        ]
        c = _aggregate_votes(results, _config(), _models("claude", "gemini"))
        assert c.final_verdict == Verdict.MALICIOUS

    def test_majority_malicious(self):
        results = [
            _result("claude", Verdict.MALICIOUS, 0.95),
            _result("gemini", Verdict.MALICIOUS, 0.85),
            _result("ollama", Verdict.SUSPICIOUS, 0.6),
        ]
        c = _aggregate_votes(results, _config(), _models("claude", "gemini", "ollama"))
        assert c.final_verdict == Verdict.MALICIOUS

    def test_disagreement_triggers_review(self):
        results = [
            _result("claude", Verdict.MALICIOUS, 0.95),
            _result("gemini", Verdict.SAFE, 0.85),
        ]
        c = _aggregate_votes(results, _config(), _models("claude", "gemini"))
        assert c.final_verdict == Verdict.NEEDS_HUMAN_REVIEW
        assert c.has_disagreement

    def test_all_errors(self):
        results = [
            _result("claude", Verdict.ERROR, 0.0),
            _result("gemini", Verdict.ERROR, 0.0),
        ]
        c = _aggregate_votes(results, _config(), _models("claude", "gemini"))
        assert c.final_verdict == Verdict.ERROR

    def test_suspicious_consensus(self):
        results = [
            _result("claude", Verdict.SUSPICIOUS, 0.8),
            _result("gemini", Verdict.SUSPICIOUS, 0.7),
        ]
        c = _aggregate_votes(results, _config(), _models("claude", "gemini"))
        assert c.final_verdict == Verdict.SUSPICIOUS

    def test_weighted_models(self):
        models = [
            ModelConfig(name="claude", backend="claude", weight=2.0),
            ModelConfig(name="ollama", backend="ollama", weight=0.5),
        ]
        results = [
            _result("claude", Verdict.MALICIOUS, 0.9),
            _result("ollama", Verdict.SAFE, 0.6),
        ]
        # Claude has much higher weight, should still trigger review due to disagreement
        c = _aggregate_votes(results, _config(), models)
        assert c.final_verdict == Verdict.NEEDS_HUMAN_REVIEW

    def test_risk_signals_aggregated(self):
        r1 = _result("claude", Verdict.SUSPICIOUS)
        r1.risk_signals = ["base64_decode", "network_call"]
        r2 = _result("gemini", Verdict.SUSPICIOUS)
        r2.risk_signals = ["network_call", "env_access"]
        c = _aggregate_votes([r1, r2], _config(), _models("claude", "gemini"))
        assert "base64_decode" in c.risk_signals
        assert "network_call" in c.risk_signals
        assert "env_access" in c.risk_signals
        # Deduplication
        assert c.risk_signals.count("network_call") == 1

    def test_single_model_fast_path(self):
        """With only 1 valid result, skip voting and return directly."""
        results = [_result("claude", Verdict.SUSPICIOUS, 0.75)]
        c = _aggregate_votes(results, _config(), _models("claude"))
        assert c.final_verdict == Verdict.SUSPICIOUS
        assert c.confidence == 0.75
        assert c.summary.startswith("Single-model")
        assert "claude" in c.summary
        assert not c.has_disagreement

    def test_single_model_fast_path_with_errors(self):
        """When multiple results exist but only 1 is valid, use fast path."""
        results = [
            _result("claude", Verdict.ERROR, 0.0),
            _result("gemini", Verdict.MALICIOUS, 0.9),
        ]
        c = _aggregate_votes(results, _config(), _models("claude", "gemini"))
        assert c.final_verdict == Verdict.MALICIOUS
        assert c.summary.startswith("Single-model")

    def test_single_model_risk_signals_preserved(self):
        """Single-model fast path preserves risk signals."""
        r = _result("claude", Verdict.SUSPICIOUS, 0.8)
        r.risk_signals = ["base64_decode", "network_call"]
        c = _aggregate_votes([r], _config(), _models("claude"))
        assert c.risk_signals == ["base64_decode", "network_call"]

    def test_zero_valid_models_returns_error(self):
        """When all models return errors, result is ERROR."""
        results = [
            _result("claude", Verdict.ERROR, 0.0),
        ]
        c = _aggregate_votes(results, _config(), _models("claude"))
        assert c.final_verdict == Verdict.ERROR
        assert "errors" in c.summary.lower()


# --- Q1: consensus error should preserve correct model_name ---
class TestConsensusErrorModelName:
    async def test_backend_error_preserves_model_name(self):
        """When a backend raises, the error result should have the correct model name."""
        config = Config(
            models=[
                ModelConfig(name="claude", backend="claude", weight=1.0),
                ModelConfig(name="gemini", backend="gemini", weight=0.9),
            ],
        )
        package = PackageInfo(name="testpkg", version="1.0.0", ecosystem="pypi")

        # Mock create_backend to return backends that fail
        from aigate.backends.base import AIBackend

        class FailingBackend(AIBackend):
            name = "failing"

            def __init__(self, backend_name: str):
                self._name = backend_name
                self.name = backend_name

            async def analyze(self, prompt, level=AnalysisLevel.L1_QUICK):
                raise RuntimeError(f"{self._name} exploded")

        with patch("aigate.consensus.create_backend") as mock_create:
            mock_create.side_effect = lambda mc: FailingBackend(mc.name)
            result = await run_consensus(
                package=package,
                risk_signals=[],
                source_code="",
                config=config,
            )

        # All should be errors — verify model names are NOT "unknown"
        error_results = [r for r in result.model_results if r.verdict == Verdict.ERROR]
        assert len(error_results) == 2
        model_names = {r.model_name for r in error_results}
        assert "unknown" not in model_names
        assert "claude" in model_names
        assert "gemini" in model_names
