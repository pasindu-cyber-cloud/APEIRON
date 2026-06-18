"""Tests for API-key + CORS startup hardening."""

import pytest

from app.config import Settings
from app.security import InsecureConfigurationError, enforce_startup_security


def test_allowed_origins_parsing(monkeypatch):
    monkeypatch.setenv("APEIRON_ENV", "development")
    monkeypatch.setenv("APEIRON_ALLOWED_ORIGINS", "http://a.test, http://b.test ,")
    s = Settings(_env_file=None)
    assert s.allowed_origins == ["http://a.test", "http://b.test"]


def test_dev_origins_fallback_when_empty(monkeypatch):
    monkeypatch.setenv("APEIRON_ENV", "development")
    monkeypatch.setenv("APEIRON_ALLOWED_ORIGINS", "")
    s = Settings(_env_file=None)
    assert s.allowed_origins == ["http://localhost:5173", "http://localhost:8080"]


def test_production_rejects_placeholder_api_key(monkeypatch):
    monkeypatch.setenv("APEIRON_ENV", "production")
    monkeypatch.setenv("APEIRON_API_KEY", "change-this-before-running")
    monkeypatch.setenv("APEIRON_ALLOWED_ORIGINS", "http://localhost:8080")
    s = Settings(_env_file=None)
    errors, _warnings = s.security_report()
    assert any("API_KEY" in e for e in errors)
    with pytest.raises(InsecureConfigurationError):
        enforce_startup_security(s)


def test_production_rejects_empty_api_key(monkeypatch):
    monkeypatch.setenv("APEIRON_ENV", "production")
    monkeypatch.setenv("APEIRON_API_KEY", "")
    monkeypatch.setenv("APEIRON_ALLOWED_ORIGINS", "http://localhost:8080")
    s = Settings(_env_file=None)
    with pytest.raises(InsecureConfigurationError):
        enforce_startup_security(s)


def test_production_rejects_wildcard_cors(monkeypatch):
    monkeypatch.setenv("APEIRON_ENV", "production")
    monkeypatch.setenv("APEIRON_API_KEY", "a-sufficiently-strong-key")
    monkeypatch.setenv("APEIRON_ALLOWED_ORIGINS", "*")
    s = Settings(_env_file=None)
    assert s.cors_is_wildcard
    assert "*" not in s.allowed_origins  # wildcard never propagated
    with pytest.raises(InsecureConfigurationError):
        enforce_startup_security(s)


def test_production_accepts_strong_config(monkeypatch):
    monkeypatch.setenv("APEIRON_ENV", "production")
    monkeypatch.setenv("APEIRON_API_KEY", "a-sufficiently-strong-key")
    monkeypatch.setenv("APEIRON_ALLOWED_ORIGINS", "https://sandbox.example.com")
    s = Settings(_env_file=None)
    errors, _warnings = s.security_report()
    assert errors == []
    enforce_startup_security(s)  # must not raise


def test_development_allows_placeholder_with_warning(monkeypatch):
    monkeypatch.setenv("APEIRON_ENV", "development")
    monkeypatch.setenv("APEIRON_API_KEY", "")
    s = Settings(_env_file=None)
    assert s.is_development
    # Should not raise in development even with auth effectively disabled.
    enforce_startup_security(s)
