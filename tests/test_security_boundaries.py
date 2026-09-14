"""Offline regression coverage for deployment and source acquisition boundaries."""

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, str(Path(__file__).parents[1] / "backend"))
from app.config import Settings
from app.core import git_ops
from app.core.source_files import read_source_text, validate_source_tree
from app.ingestion.parser import CodeParser


@pytest.fixture
def clean_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("VEXIS_") or name.lower() in Settings.model_fields:
            monkeypatch.delenv(name)


def test_default_mode_fails_closed(clean_env):
    config = Settings(_env_file=None)
    assert not config.is_dev
    with pytest.raises(RuntimeError, match="Refusing to start"):
        config.validate_secrets()


@pytest.mark.parametrize("mode", ["dev", "test", "local", "development"])
def test_explicit_local_mode(clean_env, mode):
    Settings(_env_file=None, env=mode).validate_secrets()


@pytest.mark.parametrize("name,value,expected", [
    ("env", "production", "production"),
    ("use_celery", "true", True),
    ("scan_timeout_seconds", "17", 17),
    ("max_llm_calls_per_scan", "4", 4),
    ("max_repo_size_mb", "20", 20),
    ("max_file_bytes", "123", 123),
    ("log_level", "DEBUG", "DEBUG"),
    ("excluded_path_patterns", '["/vendor/"]', ["/vendor/"]),
    ("excluded_filename_patterns", '[".min.js"]', [".min.js"]),
    ("auth_enforced", "true", True),
])
@pytest.mark.parametrize("prefix", ["", "VEXIS_"])
def test_documented_settings(clean_env, monkeypatch, name, value, expected, prefix):
    monkeypatch.setenv(prefix + name.upper(), value)
    assert getattr(Settings(_env_file=None), name) == expected


def test_prefixed_setting_wins(clean_env, monkeypatch):
    monkeypatch.setenv("ENV", "dev")
    monkeypatch.setenv("VEXIS_ENV", "production")
    assert not Settings(_env_file=None).is_dev


def production_settings(**overrides):
    values = dict(env="production", jwt_secret="j" * 40,
                  minio_secret_key="m" * 32, encryption_key=Fernet.generate_key().decode())
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.mark.parametrize("overrides", [
    {"jwt_secret": ""}, {"minio_secret_key": "short"},
    {"encryption_key": "invalid"}, {"encryption_key": ""}, {"auth_enforced": False},
])
def test_invalid_production_secrets(clean_env, overrides):
    with pytest.raises(RuntimeError):
        production_settings(**overrides).validate_secrets()


def test_valid_production_secrets(clean_env):
    production_settings().validate_secrets()


def test_worker_rejects_invalid_configuration(clean_env, monkeypatch):
    from app import celery_app
    monkeypatch.setattr(celery_app, "settings", Settings(_env_file=None))
    with pytest.raises(SystemExit, match="Refusing to start"):
        celery_app.validate_worker_settings()


def make_link(link, target, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as error:
        pytest.skip(f"Host cannot create synthetic symlink: {error}")


def test_regular_source(tmp_path):
    source = tmp_path / "safe.py"
    source.write_text("x = 1", encoding="utf-8")
    validate_source_tree(str(tmp_path))
    assert CodeParser().parse_file(str(source)).source == "x = 1"


@pytest.mark.parametrize("directory", [False, True])
def test_external_links_rejected(tmp_path, directory):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.py"
    sentinel.write_text("sentinel = 123", encoding="utf-8")
    link = repo / ("linked" if directory else "linked.py")
    make_link(link, outside if directory else sentinel, directory)
    with pytest.raises(ValueError):
        validate_source_tree(str(repo))
    with pytest.raises((ValueError, OSError)):
        CodeParser().parse_file(str(link / "sentinel.py" if directory else link))


def test_out_of_root_read_rejected(tmp_path):
    with pytest.raises(ValueError):
        read_source_text(str(tmp_path / "outside.py"), str(tmp_path / "repo"))


def test_private_clone_validation_and_cleanup(tmp_path, monkeypatch):
    checkout = tmp_path / "clone"
    checkout.mkdir()
    monkeypatch.setattr(git_ops.tempfile, "mkdtemp", lambda **_: str(checkout))
    monkeypatch.setattr(git_ops, "_run_git", AsyncMock(return_value=(0, "", "")))
    def reject(_):
        raise ValueError("synthetic unsafe checkout")
    monkeypatch.setattr(git_ops, "validate_source_tree", reject)
    with pytest.raises(ValueError):
        asyncio.run(git_ops.clone_repo("https://github.com/example/repo", "fake"))
    assert not checkout.exists()


def test_clone_timeout_cleanup(tmp_path, monkeypatch):
    checkout = tmp_path / "clone"
    checkout.mkdir()
    monkeypatch.setattr(git_ops.tempfile, "mkdtemp", lambda **_: str(checkout))
    monkeypatch.setattr(git_ops, "_run_git", AsyncMock(side_effect=TimeoutError))
    with pytest.raises(TimeoutError):
        asyncio.run(git_ops.clone_repo("https://github.com/example/repo", "fake"))
    assert not checkout.exists()


def test_github_token_provider_binding():
    with pytest.raises(ValueError, match="github.com"):
        asyncio.run(git_ops.clone_repo("https://gitlab.com/example/repo", "fake"))


def test_cached_clone_rejects_link(tmp_path, monkeypatch):
    url = "https://github.com/example/repo"
    cache = tmp_path / "cache"
    checkout = cache / git_ops._cache_key(url)
    checkout.mkdir(parents=True)
    sentinel = tmp_path / "sentinel.py"
    sentinel.write_text("sentinel = 123", encoding="utf-8")
    make_link(checkout / "linked.py", sentinel)
    scan = tmp_path / "scan"
    scan.mkdir()
    monkeypatch.setattr(git_ops, "CLONE_CACHE_DIR", str(cache))
    monkeypatch.setattr(git_ops.tempfile, "mkdtemp", lambda **_: str(scan))
    monkeypatch.setattr(git_ops, "_run_git", AsyncMock(return_value=(0, "", "")))
    with pytest.raises(ValueError):
        asyncio.run(git_ops.clone_repo(url))
    assert not scan.exists()
    assert sentinel.read_text() == "sentinel = 123"


@pytest.mark.parametrize("incremental", [False, True])
def test_scan_preserves_project_context(tmp_path, monkeypatch, incremental):
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from app.core import orchestrator, incremental as baseline, storage

    (tmp_path / "entry.py").write_text(
        'from flask import request\nfrom db import lookup\n'
        'def route():\n    lookup(request.args.get("q"))\n', encoding="utf-8"
    )
    (tmp_path / "db.py").write_text(
        'def lookup(q):\n    cursor.execute("SELECT " + q)\n', encoding="utf-8"
    )
    scan = SimpleNamespace(source_type="file_upload", source_ref=str(tmp_path),
                           config={"incremental": incremental}, user_id=None, stats={})
    db = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = scan
    db.execute.return_value = result
    db.__aenter__.return_value = db
    monkeypatch.setattr(orchestrator, "AsyncSessionLocal", lambda: db)
    monkeypatch.setattr(orchestrator, "_broadcast", AsyncMock())
    monkeypatch.setattr(storage, "upload_code_snapshot", AsyncMock())
    changed = AsyncMock(return_value={"entry.py"})
    monkeypatch.setattr(baseline, "get_changed_files_for_scan", changed)
    observed = []
    class AnalysisObserved(BaseException):
        pass
    async def inspect_project(parsed, *args):
        observed.extend(Path(file.path).name for file in parsed)
        raise AnalysisObserved()
    monkeypatch.setattr(orchestrator, "_run_cross_file", inspect_project)
    with pytest.raises(AnalysisObserved):
        asyncio.run(orchestrator._run_scan_impl("00000000-0000-0000-0000-000000000001"))
    assert set(observed) == {"entry.py", "db.py"}
    changed.assert_not_called()
    assert scan.stats["analysis_mode"] == "full"
    assert scan.stats["incremental_skipped"] == 0
