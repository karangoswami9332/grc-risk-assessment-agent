"""Fail-safe authentication configuration for production deployments."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from grc_agent.api.app import create_app
from grc_agent.config import Settings, assert_auth_configuration, get_settings

_PROD_SECRET = "production-test-secret-at-least-32-chars!!"


def _prod_settings(tmp_path: Path, **overrides: object) -> Settings:
    base: dict[str, object] = {
        "database_url": f"sqlite:///{(tmp_path / 'prod.db').as_posix()}",
        "app_env": "production",
        "auth_enabled": True,
        "jwt_algorithm": "HS256",
        "jwt_secret": _PROD_SECRET,
        "jwt_issuer": "grc-prod",
        "jwt_audience": "grc-api",
        "jwt_public_key": "",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_production_refuses_auth_disabled_via_assert() -> None:
    with pytest.raises(ValueError, match="AUTH_ENABLED must be true"):
        assert_auth_configuration(
            Settings(app_env="production", auth_enabled=False)
        )


def test_production_create_app_refuses_unauthenticated(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="AUTH_ENABLED must be true"):
        create_app(
            Settings(
                database_url=f"sqlite:///{(tmp_path / 'p.db').as_posix()}",
                app_env="production",
                auth_enabled=False,
            )
        )


def test_manual_production_settings_missing_issuer_rejected(tmp_path: Path) -> None:
    settings = _prod_settings(tmp_path, jwt_issuer="", jwt_audience="grc-api")
    with pytest.raises(ValueError, match="JWT_ISSUER and JWT_AUDIENCE"):
        assert_auth_configuration(settings)
    with pytest.raises(ValueError, match="JWT_ISSUER and JWT_AUDIENCE"):
        create_app(settings)


def test_manual_production_settings_missing_audience_rejected(tmp_path: Path) -> None:
    settings = _prod_settings(tmp_path, jwt_audience="")
    with pytest.raises(ValueError, match="JWT_ISSUER and JWT_AUDIENCE"):
        create_app(settings)


def test_manual_production_settings_missing_hs_secret_rejected(tmp_path: Path) -> None:
    settings = _prod_settings(tmp_path, jwt_secret="")
    with pytest.raises(ValueError, match="JWT_SECRET is required"):
        assert_auth_configuration(settings)
    with pytest.raises(ValueError, match="JWT_SECRET is required"):
        create_app(settings)


def test_manual_production_settings_complete_accepted(tmp_path: Path) -> None:
    settings = _prod_settings(tmp_path)
    assert_auth_configuration(settings)
    app = create_app(settings)
    assert app.state.settings.auth_enabled is True


def test_get_settings_production_requires_explicit_auth_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GRC_APP_ENV", "production")
    monkeypatch.delenv("AUTH_ENABLED", raising=False)
    with pytest.raises(ValueError, match="AUTH_ENABLED must be explicitly set"):
        get_settings()


def test_get_settings_production_rejects_auth_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_APP_ENV", "production")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    with pytest.raises(ValueError, match="not allowed"):
        get_settings()


def test_get_settings_production_requires_issuer_audience(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GRC_APP_ENV", "production")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("JWT_SECRET", _PROD_SECRET)
    monkeypatch.setenv("JWT_ALGORITHM", "HS256")
    monkeypatch.delenv("JWT_ISSUER", raising=False)
    monkeypatch.delenv("JWT_AUDIENCE", raising=False)
    with pytest.raises(ValueError, match="JWT_ISSUER and JWT_AUDIENCE"):
        get_settings()


def test_get_settings_production_ok_with_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRC_APP_ENV", "production")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("JWT_SECRET", _PROD_SECRET)
    monkeypatch.setenv("JWT_ALGORITHM", "HS256")
    monkeypatch.setenv("JWT_ISSUER", "grc-prod")
    monkeypatch.setenv("JWT_AUDIENCE", "grc-api")
    settings = get_settings()
    assert settings.app_env == "production"
    assert settings.auth_enabled is True


def test_development_allows_auth_disabled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GRC_APP_ENV", "development")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    settings = get_settings()
    assert settings.auth_enabled is False
    client = TestClient(
        create_app(
            Settings(
                database_url=f"sqlite:///{(tmp_path / 'd.db').as_posix()}",
                app_env="development",
                auth_enabled=False,
            )
        )
    )
    assert client.get("/assessments").status_code == 200
