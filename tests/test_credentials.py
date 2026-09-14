"""Credential isolation checks with fake users and transports."""

import asyncio
import base64
import os
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import FastAPI

sys.path.insert(0, str(Path(__file__).parents[1] / "backend"))
from app.api import deps
from app.api.routes import auth, autofix
from app.core import git_ops
from app.database import get_db


class IdentityOnlyUser:
    id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    github_login = "synthetic"
    email = "synthetic@example.invalid"

    @property
    def github_token_plain(self):
        raise AssertionError("Authentication must not decrypt repository credentials")


@pytest.mark.parametrize("method", ["api_key", "jwt"])
def test_authentication_does_not_load_github_credentials(monkeypatch, method):
    from app.core import auth as core_auth
    monkeypatch.setattr(core_auth, "decode_token", lambda _: {"sub": str(IdentityOnlyUser.id)})
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = IdentityOnlyUser()
    db.execute.return_value = result
    user = asyncio.run(deps.get_current_user(
        authorization="Bearer synthetic" if method == "jwt" else None,
        x_vexis_api_key="synthetic" if method == "api_key" else None, db=db,
    ))
    assert user["auth_method"] == method
    assert "github_token" not in user


def test_public_identity_excludes_internal_fields():
    app = FastAPI()
    app.include_router(auth.router)
    app.dependency_overrides[deps.require_user] = lambda: {
        "id": IdentityOnlyUser.id, "login": "synthetic", "email": None,
        "github_token": "FAKE_SECRET", "api_key": "FAKE_KEY", "auth_method": "jwt",
    }
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/auth/me")
            assert response.status_code == 200
            assert response.json() == {"id": str(IdentityOnlyUser.id), "login": "synthetic", "email": None}
    asyncio.run(request())


def test_ci_key_cannot_open_pull_request(monkeypatch):
    app = FastAPI()
    app.include_router(autofix.router)
    db = AsyncMock()
    row = MagicMock()
    row.scalar_one_or_none.return_value = IdentityOnlyUser()
    db.execute.return_value = row
    app.dependency_overrides[get_db] = lambda: db
    load_finding = AsyncMock()
    monkeypatch.setattr(autofix, "_load_owned_finding", load_finding)
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                f"/finding/{IdentityOnlyUser.id}/pr", json={},
                headers={"X-VEXIS-API-Key": "synthetic"},
            )
            assert response.status_code == 403
    asyncio.run(request())
    load_finding.assert_not_called()


def test_signed_in_user_keeps_pr_access():
    user = {"id": IdentityOnlyUser.id, "auth_method": "jwt"}
    assert asyncio.run(deps.require_repository_write(user)) is user


def test_private_clone_keeps_credentials_out_of_arguments(tmp_path, monkeypatch):
    checkout = tmp_path / "clone"
    checkout.mkdir()
    monkeypatch.setattr(git_ops.tempfile, "mkdtemp", lambda **_: str(checkout))
    git = AsyncMock(return_value=(0, "", ""))
    monkeypatch.setattr(git_ops, "_run_git", git)
    token = "SYNTHETIC_GITHUB_TOKEN"
    url = "https://github.com/example/repo"
    assert asyncio.run(git_ops.clone_repo(url, token)) == str(checkout)
    args = git.call_args.args
    assert url in args
    assert all(token not in arg and "x-access-token:" not in arg for arg in args)
    env = git.call_args.kwargs["env"]
    encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {encoded}"
    assert env["GIT_CONFIG_VALUE_1"] == ""
    assert env["GIT_CONFIG_VALUE_2"] == "false"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull


def test_git_auth_does_not_inherit_trace_or_config(monkeypatch):
    monkeypatch.setenv("GIT_TRACE", "1")
    monkeypatch.setenv("GIT_CURL_VERBOSE", "1")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "unsafe")
    before = dict(os.environ)
    env = git_ops._authenticated_git_env("fake")
    assert "GIT_TRACE" not in env
    assert "GIT_CURL_VERBOSE" not in env
    assert "GIT_CONFIG_PARAMETERS" not in env
    assert dict(os.environ) == before


def test_clone_errors_do_not_expose_credentials(tmp_path, monkeypatch):
    checkout = tmp_path / "clone"
    checkout.mkdir()
    monkeypatch.setattr(git_ops.tempfile, "mkdtemp", lambda **_: str(checkout))
    monkeypatch.setattr(git_ops, "_run_git", AsyncMock(return_value=(128, "", "FAKE_SECRET")))
    with pytest.raises(RuntimeError) as error:
        asyncio.run(git_ops.clone_repo("https://github.com/example/repo", "FAKE_SECRET"))
    assert "FAKE_SECRET" not in str(error.value)
    assert not checkout.exists()
