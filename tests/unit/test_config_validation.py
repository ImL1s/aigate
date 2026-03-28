"""Tests for configuration validation."""

from __future__ import annotations

import logging

import pytest

from aigate.config import Config, ModelConfig, ThresholdConfig
from aigate.config_validator import ConfigValidationError, validate_config


def test_valid_config_passes():
    config = Config()
    validate_config(config)  # Should not raise


def test_invalid_backend_raises():
    config = Config(models=[ModelConfig(name="test", backend="nonexistent", weight=1.0)])
    with pytest.raises(ConfigValidationError, match="backend"):
        validate_config(config)


def test_weight_out_of_range_raises():
    config = Config(models=[ModelConfig(name="test", backend="claude", weight=2.5)])
    with pytest.raises(ConfigValidationError, match="weight"):
        validate_config(config)


def test_negative_weight_raises():
    config = Config(models=[ModelConfig(name="test", backend="claude", weight=-0.1)])
    with pytest.raises(ConfigValidationError, match="weight"):
        validate_config(config)


def test_threshold_out_of_range_raises():
    config = Config(thresholds=ThresholdConfig(malicious=1.5))
    with pytest.raises(ConfigValidationError, match="threshold"):
        validate_config(config)


def test_negative_timeout_raises():
    config = Config(
        models=[ModelConfig(name="test", backend="claude", weight=1.0, timeout_seconds=-10)]
    )
    with pytest.raises(ConfigValidationError, match="timeout"):
        validate_config(config)


def test_invalid_ecosystem_raises():
    config = Config(ecosystems=["pypi", "npm", "rubygems"])
    with pytest.raises(ConfigValidationError, match="ecosystem"):
        validate_config(config)


def test_no_enabled_models_warns(caplog):
    config = Config(models=[ModelConfig(name="test", backend="claude", weight=1.0, enabled=False)])
    with caplog.at_level(logging.WARNING):
        validate_config(config)
    assert "No enabled models" in caplog.text


def test_duplicate_model_names_raises():
    config = Config(
        models=[
            ModelConfig(name="dup", backend="claude", weight=1.0),
            ModelConfig(name="dup", backend="gemini", weight=1.0),
        ]
    )
    with pytest.raises(ConfigValidationError, match="Duplicate"):
        validate_config(config)
