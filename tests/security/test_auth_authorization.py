"""Authentication and authorization security tests (local JWT layer)."""

from __future__ import annotations

import base64
import json
import logging
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient

from grc_agent.api.app import create_app
from grc_agent.config import Settings
from grc_agent.observability.audit import (
    AUTHENTICATION_FAILED,
    AUTHENTICATION_SUCCEEDED,
    AUTHORIZATION_DENIED,
    AUDIT_LOGGER_NAME,
    parse_audit_records,
)

TEST_SECRET = "unit-test-only-hmac-secret-not-for-production!!"
TEST_ISSUER = "grc-agent-test"
TEST_AUDIENCE = "grc-agent-api"


def _auth_settings(tmp_path: Path, **overrides: Any) -> Settings:
    base = dict(
        database_url=f"sqlite:///{(tmp_path / 'auth.db').as_posix()}",
        risk_agent="mock",
        rag_enabled=False,
        auth_enabled=True,
        jwt_algorithm="HS256",
        jwt_issuer=TEST_ISSUER,
        jwt_audience=TEST_AUDIENCE,
        jwt_secret=TEST_SECRET,
        jwt_public_key="",
    )
    base.update(overrides)
    return Settings(**base)


def mint_token(
    *,
    sub: str = "user-a",
    role: str = "assessor",
    tenant_id: str = "tenant-a",
    secret: str = TEST_SECRET,
    issuer: str = TEST_ISSUER,
    audience: str = TEST_AUDIENCE,
    algorithm: str = "HS256",
    exp_delta: int = 3600,
    extra_claims: dict[str, Any] | None = None,
    omit_exp: bool = False,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": sub,
        "role": role,
        "tenant_id": tenant_id,
        "iat": now,
        "iss": issuer,
        "aud": audience,
    }
    if not omit_exp:
        claims["exp"] = now + exp_delta
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(claims, secret, algorithm=algorithm)


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(_auth_settings(tmp_path)))


@pytest.fixture
def auth_client_caplog(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> tuple[TestClient, pytest.LogCaptureFixture]:
    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER_NAME)
    client = TestClient(create_app(_auth_settings(tmp_path)))
    return client, caplog


# --- Authentication ---


def test_missing_authorization_header_returns_401(auth_client: TestClient) -> None:
    response = auth_client.get("/assessments")
    assert response.status_code == 401
    body = response.json()
    assert body["detail"] == "Not authenticated"
    assert TEST_SECRET not in response.text


def test_malformed_authorization_header_returns_401(auth_client: TestClient) -> None:
    response = auth_client.get("/assessments", headers={"Authorization": "Token not-a-bearer"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"


def test_invalid_jwt_returns_401(auth_client: TestClient) -> None:
    response = auth_client.get("/assessments", headers=auth_header("not.a.jwt"))
    assert response.status_code == 401


def test_expired_jwt_returns_401(auth_client: TestClient) -> None:
    token = mint_token(exp_delta=-120)
    response = auth_client.get("/assessments", headers=auth_header(token))
    assert response.status_code == 401


def test_wrong_issuer_returns_401(auth_client: TestClient) -> None:
    token = mint_token(issuer="evil-issuer")
    response = auth_client.get("/assessments", headers=auth_header(token))
    assert response.status_code == 401


def test_wrong_audience_returns_401(auth_client: TestClient) -> None:
    token = mint_token(audience="wrong-api")
    response = auth_client.get("/assessments", headers=auth_header(token))
    assert response.status_code == 401


def test_invalid_signature_returns_401(auth_client: TestClient) -> None:
    token = mint_token(secret="different-secret-value-xxxxxxxx!!")
    response = auth_client.get("/assessments", headers=auth_header(token))
    assert response.status_code == 401


def test_alg_none_attack_rejected(auth_client: TestClient) -> None:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "sub": "attacker",
                "role": "admin",
                "tenant_id": "tenant-a",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "iss": TEST_ISSUER,
                "aud": TEST_AUDIENCE,
            }
        ).encode()
    ).rstrip(b"=")
    token = f"{header.decode()}.{payload.decode()}."
    response = auth_client.get("/assessments", headers=auth_header(token))
    assert response.status_code == 401


def test_modified_jwt_claims_rejected(auth_client: TestClient) -> None:
    token = mint_token(role="viewer", tenant_id="tenant-a")
    parts = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    payload["role"] = "admin"
    forged = (
        parts[0]
        + "."
        + base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
        + "."
        + parts[2]
    )
    response = auth_client.get("/assessments", headers=auth_header(forged))
    assert response.status_code == 401


def test_valid_jwt_allows_access(auth_client: TestClient) -> None:
    token = mint_token(role="viewer")
    response = auth_client.get("/assessments", headers=auth_header(token))
    assert response.status_code == 200
    assert response.json()["items"] == []


# --- Authorization ---


def test_admin_can_create_and_list(auth_client: TestClient) -> None:
    token = mint_token(sub="admin-1", role="admin", tenant_id="tenant-a")
    created = auth_client.post(
        "/assessments",
        headers=auth_header(token),
        json={"title": "Admin A", "scenario": "Scenario"},
    )
    assert created.status_code == 201
    listed = auth_client.get("/assessments", headers=auth_header(token))
    assert listed.status_code == 200
    assert len(listed.json()["items"]) == 1


def test_assessor_can_create_and_run_risk_assessment(auth_client: TestClient) -> None:
    token = mint_token(role="assessor", tenant_id="tenant-a")
    created = auth_client.post(
        "/assessments",
        headers=auth_header(token),
        json={"title": "Assessor A", "scenario": "Scenario"},
    )
    assert created.status_code == 201
    risk = auth_client.post(
        "/risk-assessments",
        headers=auth_header(token),
        json={"scenario": "Cloud admin has excessive privileges"},
    )
    assert risk.status_code == 200
    assert "risk_score" in risk.json()


def test_viewer_can_read_but_not_write(auth_client: TestClient) -> None:
    writer = mint_token(sub="writer", role="assessor", tenant_id="tenant-a")
    viewer = mint_token(sub="reader", role="viewer", tenant_id="tenant-a")
    created = auth_client.post(
        "/assessments",
        headers=auth_header(writer),
        json={"title": "Shared", "scenario": "Scenario"},
    )
    assessment_id = created.json()["id"]

    assert auth_client.get("/assessments", headers=auth_header(viewer)).status_code == 200
    assert auth_client.get(f"/assessments/{assessment_id}", headers=auth_header(viewer)).status_code == 200

    denied = auth_client.post(
        "/assessments",
        headers=auth_header(viewer),
        json={"title": "Nope", "scenario": "Scenario"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Forbidden"

    nested = auth_client.post(
        f"/assessments/{assessment_id}/risks",
        headers=auth_header(viewer),
        json={"title": "R", "likelihood": 2, "impact": 2},
    )
    assert nested.status_code == 403

    orchestrated = auth_client.post(
        "/risk-assessments",
        headers=auth_header(viewer),
        json={"scenario": "Should be denied"},
    )
    assert orchestrated.status_code == 403


def test_authorization_denied_correlated_with_request_id(
    auth_client_caplog: tuple[TestClient, pytest.LogCaptureFixture],
) -> None:
    client, caplog = auth_client_caplog
    viewer = mint_token(role="viewer", tenant_id="tenant-a")
    request_id = "authz-corr-123"
    response = client.post(
        "/assessments",
        headers={**auth_header(viewer), "X-Request-ID": request_id},
        json={"title": "Nope", "scenario": "Scenario"},
    )
    assert response.status_code == 403
    assert response.headers.get("X-Request-ID") == request_id
    events = parse_audit_records(caplog.text)
    denied = [e for e in events if e.get("event") == AUTHORIZATION_DENIED]
    assert denied
    assert denied[-1]["correlation_id"] == request_id


# --- Multi-tenancy ---


def test_tenant_isolation_read_modify_list(auth_client: TestClient) -> None:
    token_a = mint_token(sub="a", role="assessor", tenant_id="tenant-a")
    token_b = mint_token(sub="b", role="assessor", tenant_id="tenant-b")

    created = auth_client.post(
        "/assessments",
        headers=auth_header(token_a),
        json={"title": "Tenant A only", "scenario": "Scenario A"},
    )
    assert created.status_code == 201
    assessment_id = created.json()["id"]
    assert created.json()["tenant_id"] == "tenant-a"

    # Own tenant OK
    assert auth_client.get(f"/assessments/{assessment_id}", headers=auth_header(token_a)).status_code == 200

    # Cross-tenant read → 404 (no enumeration)
    cross_get = auth_client.get(f"/assessments/{assessment_id}", headers=auth_header(token_b))
    assert cross_get.status_code == 404
    assert "traceback" not in cross_get.text.lower()
    assert TEST_SECRET not in cross_get.text

    # Cross-tenant modify → 404
    cross_mod = auth_client.post(
        f"/assessments/{assessment_id}/risks",
        headers=auth_header(token_b),
        json={"title": "Inject", "likelihood": 1, "impact": 1},
    )
    assert cross_mod.status_code == 404

    # List is tenant-scoped for non-admin
    listed_b = auth_client.get("/assessments", headers=auth_header(token_b))
    assert listed_b.status_code == 200
    assert listed_b.json()["items"] == []

    listed_a = auth_client.get("/assessments", headers=auth_header(token_a))
    assert len(listed_a.json()["items"]) == 1


def test_admin_can_see_other_tenant(auth_client: TestClient) -> None:
    assessor = mint_token(sub="a", role="assessor", tenant_id="tenant-a")
    admin = mint_token(sub="admin", role="admin", tenant_id="ops")
    created = auth_client.post(
        "/assessments",
        headers=auth_header(assessor),
        json={"title": "A", "scenario": "S"},
    )
    assessment_id = created.json()["id"]
    assert auth_client.get(f"/assessments/{assessment_id}", headers=auth_header(admin)).status_code == 200
    listed = auth_client.get("/assessments", headers=auth_header(admin))
    assert any(item["id"] == assessment_id for item in listed.json()["items"])


# --- Security hygiene ---


def test_tokens_never_appear_in_audit_logs(
    auth_client_caplog: tuple[TestClient, pytest.LogCaptureFixture],
) -> None:
    client, caplog = auth_client_caplog
    token = mint_token(role="assessor")
    client.get("/assessments", headers=auth_header(token))
    client.get("/assessments", headers=auth_header("bad.token.value"))
    blob = caplog.text
    assert token not in blob
    assert "Bearer " not in blob
    assert TEST_SECRET not in blob
    events = parse_audit_records(blob)
    assert any(e.get("event") == AUTHENTICATION_SUCCEEDED for e in events)
    assert any(e.get("event") == AUTHENTICATION_FAILED for e in events)


def test_error_responses_have_no_traceback_or_secrets(auth_client: TestClient) -> None:
    token = mint_token(secret="wrong-secret-xxxxxxxxxxxxxxxxxxx")
    response = auth_client.get("/assessments", headers=auth_header(token))
    assert response.status_code == 401
    text = response.text.lower()
    assert "traceback" not in text
    assert "jwt_secret" not in text
    assert TEST_SECRET not in response.text
    assert "stack" not in text


def test_auth_disabled_keeps_existing_open_local_mode(tmp_path: Path) -> None:
    """Regression: AUTH_ENABLED=false preserves prior unauthenticated local API."""
    client = TestClient(
        create_app(
            Settings(
                database_url=f"sqlite:///{(tmp_path / 'open.db').as_posix()}",
                app_env="development",
                auth_enabled=False,
            )
        )
    )
    response = client.post("/assessments", json={"title": "Open", "scenario": "Local"})
    assert response.status_code == 201
    assert response.json()["tenant_id"] == "local"


def test_forged_role_tenant_subject_in_unsigned_payload_rejected(auth_client: TestClient) -> None:
    token = mint_token(role="viewer", tenant_id="tenant-a", sub="user-a")
    for claim, value in (("role", "admin"), ("tenant_id", "tenant-b"), ("sub", "victim")):
        parts = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        payload[claim] = value
        forged = (
            parts[0]
            + "."
            + base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
            .rstrip(b"=")
            .decode()
            + "."
            + parts[2]
        )
        response = auth_client.get("/assessments", headers=auth_header(forged))
        assert response.status_code == 401, claim


def test_algorithm_confusion_hs256_rejected_when_rs256_configured(tmp_path: Path) -> None:
    """HS256 token must not verify under RS256 config (public key must not be HMAC secret)."""
    public_pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n"
        "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n"
        "+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuamOefLqIBxSfTAue\n"
        "xuoWokvhWXJsWbvbvGhXrff1R93VkYcxgz2C9MRaLjsCE4R1mA/yTmGk1YiV/\n"
        "J7OgbYoWKmFITnmPCC8nDE6zr4BFzuNLQuAnELxwDfkRi/26/rMfM4yVXqf4\n"
        "uUxQIDAQAB\n"
        "-----END PUBLIC KEY-----"
    )
    client = TestClient(
        create_app(
            _auth_settings(
                tmp_path,
                jwt_algorithm="RS256",
                jwt_secret="",
                jwt_public_key=public_pem,
            )
        )
    )
    # Craft HS256 manually (PyJWT refuses to encode with a PEM as HMAC secret).
    import hashlib
    import hmac as hmac_mod

    def _b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    now = int(time.time())
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(
        json.dumps(
            {
                "sub": "attacker",
                "role": "admin",
                "tenant_id": "tenant-a",
                "iat": now,
                "exp": now + 3600,
                "iss": TEST_ISSUER,
                "aud": TEST_AUDIENCE,
            },
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode()
    signature = _b64(hmac_mod.new(public_pem.encode(), signing_input, hashlib.sha256).digest())
    confused = f"{header}.{payload}.{signature}"
    response = client.get("/assessments", headers=auth_header(confused))
    assert response.status_code == 401
    assert "traceback" not in response.text.lower()
    assert "BEGIN PUBLIC KEY" not in response.text


def test_header_alg_mismatch_rejected(auth_client: TestClient) -> None:
    # Server is HS256; token signed with HS512 → header alg mismatch / reject.
    claims = {
        "sub": "user-a",
        "role": "admin",
        "tenant_id": "tenant-a",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
    }
    token = jwt.encode(claims, TEST_SECRET + "-pad-for-hs512-min-key-length!!", algorithm="HS512")
    response = auth_client.get("/assessments", headers=auth_header(token))
    assert response.status_code == 401


def test_client_cannot_spoof_tenant_or_owner_in_body(auth_client: TestClient) -> None:
    token = mint_token(sub="attacker", role="assessor", tenant_id="tenant-a")
    response = auth_client.post(
        "/assessments",
        headers=auth_header(token),
        json={
            "title": "Spoof attempt",
            "scenario": "test",
            "tenant_id": "victim-tenant",
            "owner_subject": "victim-user",
        },
    )
    # Request schema forbids client-supplied ownership fields.
    assert response.status_code == 422
    detail_text = json.dumps(response.json())
    assert "traceback" not in detail_text.lower()
    assert TEST_SECRET not in detail_text

    ok = auth_client.post(
        "/assessments",
        headers=auth_header(token),
        json={"title": "Owned", "scenario": "test"},
    )
    assert ok.status_code == 201
    body = ok.json()
    assert body["tenant_id"] == "tenant-a"
    assert body["owner_subject"] == "attacker"
    assert body["tenant_id"] != "victim-tenant"
    assert body["owner_subject"] != "victim-user"


def test_nested_risks_cross_tenant_returns_404(auth_client: TestClient) -> None:
    token_a = mint_token(sub="a", role="assessor", tenant_id="tenant-a")
    token_b = mint_token(sub="b", role="assessor", tenant_id="tenant-b")
    created = auth_client.post(
        "/assessments",
        headers=auth_header(token_a),
        json={"title": "A", "scenario": "S"},
    )
    assessment_id = created.json()["id"]
    auth_client.post(
        f"/assessments/{assessment_id}/risks",
        headers=auth_header(token_a),
        json={"title": "R", "likelihood": 3, "impact": 3},
    )
    cross = auth_client.get(
        f"/assessments/{assessment_id}/risks",
        headers=auth_header(token_b),
    )
    assert cross.status_code == 404


def test_audit_redacts_accidentally_passed_token_fields() -> None:
    from grc_agent.observability.audit import emit_audit_event

    payload = emit_audit_event(
        "authentication_failed",
        reason="test",
        token="super-secret-jwt-value",
        authorization="Bearer leak",
        jwt_secret=TEST_SECRET,
        subject="user-a",
    )
    assert "token" not in payload
    assert "authorization" not in payload
    assert "jwt_secret" not in payload
    assert payload["subject"] == "user-a"
    assert payload["reason"] == "test"


def test_auth_does_not_bypass_risk_engine_scoring(auth_client: TestClient) -> None:
    token = mint_token(role="assessor", tenant_id="tenant-a")
    response = auth_client.post(
        "/risk-assessments",
        headers=auth_header(token),
        json={
            "scenario": "Cloud admin has excessive privileges",
            "risk_score": 1,
            "risk_rating": "low",
        },
    )
    # Score fields forbidden on request schema; auth must not weaken that.
    assert response.status_code == 422
    ok = auth_client.post(
        "/risk-assessments",
        headers=auth_header(token),
        json={"scenario": "Cloud admin has excessive privileges"},
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["risk_score"] == body["scored_risks"][0]["risk_score"]
    assert isinstance(body["risk_score"], int)
