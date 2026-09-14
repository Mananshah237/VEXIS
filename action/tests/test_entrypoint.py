"""Exercise action control flow with synthetic HTTP responses only."""

import importlib.util
from pathlib import Path

import httpx
import pytest


@pytest.fixture
def action(monkeypatch):
    monkeypatch.setenv("VEXIS_API_URL", "https://example.invalid")
    monkeypatch.setenv("VEXIS_API_KEY", "synthetic")
    spec = importlib.util.spec_from_file_location(
        "vexis_action", Path(__file__).parents[1] / "entrypoint.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "GITHUB_WORKSPACE", str(Path(__file__).parent))
    monkeypatch.setattr(module, "SCAN_PATH", ".")
    monkeypatch.setattr(module, "THRESHOLD_RANK", 3)
    monkeypatch.setattr(module, "collect_source", lambda _: "x = 1")
    monkeypatch.setattr(module, "submit_scan", lambda _: "scan")
    monkeypatch.setattr(module, "poll_scan", lambda _: {"status": "complete"})
    outputs = {}
    monkeypatch.setattr(module, "set_output", outputs.__setitem__)
    module.test_outputs = outputs
    return module


def transport(monkeypatch, action, handler):
    client = httpx.Client
    monkeypatch.setattr(
        action.httpx, "Client",
        lambda **kwargs: client(transport=httpx.MockTransport(handler), **kwargs),
    )


def page(findings, number=1):
    return {"findings": findings, "page": number, "per_page": 100}


def finding(number, severity="low"):
    return {"id": str(number), "severity": severity}


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_http_errors_fail_action(action, monkeypatch, capsys, status):
    transport(monkeypatch, action, lambda _: httpx.Response(status, json={"detail": "error"}))
    assert action.main() == 1
    assert "findings-count" not in action.test_outputs
    assert "check passed" not in capsys.readouterr().out


@pytest.mark.parametrize("payload", [
    {}, [], page(None), page({}), page([None]), page([{}]),
    page([{"id": "1", "severity": "unknown"}]),
    page([finding(1)], 2), {"findings": []},
    page([finding(1), finding(1)]), page([finding(i) for i in range(101)]),
])
def test_invalid_schema_fails(action, monkeypatch, payload):
    transport(monkeypatch, action, lambda _: httpx.Response(200, json=payload))
    assert action.main() == 1
    assert "findings-count" not in action.test_outputs


def test_invalid_json_fails(action, monkeypatch):
    transport(monkeypatch, action, lambda _: httpx.Response(200, text="not json"))
    assert action.main() == 1


def test_network_error_fails(action, monkeypatch):
    def handler(request):
        raise httpx.ReadTimeout("synthetic timeout", request=request)
    transport(monkeypatch, action, handler)
    assert action.main() == 1


@pytest.mark.parametrize("second_page", [
    httpx.Response(500, json={"detail": "error"}),
    httpx.Response(200, json=page([finding(0)], 2)),
    httpx.Response(200, json=page([], 1)),
])
def test_partial_results_fail(action, monkeypatch, second_page):
    def handler(request):
        if request.url.params["page"] == "1":
            return httpx.Response(200, json=page([finding(i) for i in range(100)]))
        return second_page
    transport(monkeypatch, action, handler)
    assert action.main() == 1
    assert "findings-count" not in action.test_outputs


@pytest.mark.parametrize("tail, expected", [([], 0), ([finding(100, "high")], 1)])
def test_complete_pagination(action, monkeypatch, tail, expected):
    requested = []
    def handler(request):
        number = int(request.url.params["page"])
        requested.append(number)
        batch = [finding(i) for i in range(100)] if number == 1 else tail
        return httpx.Response(200, json=page(batch, number))
    transport(monkeypatch, action, handler)
    assert action.main() == expected
    assert requested == [1, 2]
    assert action.test_outputs["findings-count"] == str(100 + len(tail))


def test_valid_empty_results_pass(action, monkeypatch):
    transport(monkeypatch, action, lambda _: httpx.Response(200, json=page([])))
    assert action.main() == 0
    assert action.test_outputs["findings-count"] == "0"
