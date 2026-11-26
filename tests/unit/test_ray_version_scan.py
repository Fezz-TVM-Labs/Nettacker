"""Behavioural tests for the ray_version_scan module.

These tests load the shipped module definition and exercise its version
detection regex exactly the way the HTTP engine does (``re.findall`` on the
response body, then joined into the log line). A Ray dashboard answers its ``/api/version`` route with JSON that holds ``ray_version``; from Ray 2.52 on, a server with token authentication turned on asks for the token first, so the module stays quiet there. Like the other
``*_version_scan`` modules this is a fingerprint only: it logs the version and
makes no claim about whether the build is vulnerable.
"""

import re
import time
from pathlib import Path

import pytest
import yaml

MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "nettacker" / "modules" / "scan" / "ray_version.yaml"
)


@pytest.fixture(scope="module")
def module():
    # Nettacker runs str.format() over the module text before it parses the YAML
    # (nettacker/core/template.py), so a stray single brace breaks loading. Do the same here.
    text = MODULE_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(text.format(user_agent="nettacker-test", target="127.0.0.1"))


@pytest.fixture(scope="module")
def step(module):
    return module["payloads"][0]["steps"][0]


@pytest.fixture(scope="module")
def content_regex(step):
    return re.compile(step["response"]["conditions"]["content"]["regex"])


def extract_version(content_regex, body):
    """Reproduce how the engine turns the content condition into a log value.

    ``http.response_conditions_matched`` runs ``re.findall`` over the body and
    ``base`` joins the (de-duplicated) matches with spaces for the log line, so
    a single-capture-group regex logs just the captured version string.
    """
    matches = re.findall(content_regex, body)
    return " ".join(sorted(set(matches)))


def test_module_metadata(module):
    info = module["info"]
    # ArgParser.load_modules derives the module id as "<file stem>_<parent dir>".
    assert info["name"] == f"{MODULE_PATH.stem.replace('_version', '')}_version_scan"
    assert info["name"] == "ray_version_scan"
    assert info["severity"] == 3
    assert "scan" in info["profiles"]
    assert "ray" in info["profiles"]
    assert "info_severity" in info["profiles"]


def test_targets_expected_endpoint_and_ports(step):
    fuzzer = step["url"]["nettacker_fuzzer"]
    assert fuzzer["input_format"].endswith("/api/version")
    data = fuzzer["data"]
    assert data["schema"] == ["http", "https"]
    assert set(data["ports"]) == {80, 443, 8265}


def test_requires_http_200_and_logs_the_capture(step):
    conditions = step["response"]["conditions"]
    assert conditions["status_code"]["regex"] == "200"
    assert step["response"]["condition_type"] == "and"
    assert step["response"]["log"] == "response_dependent['content']"


@pytest.mark.parametrize(
    "body, expected",
    [
        (
            '{"version": "4", "ray_version": "2.50.1", "ray_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "session_name": "session_2026-11-26_00-00-00_000000_1"}',
            "2.50.1",
        ),
        (
            '{"version":"4","ray_version":"2.61.0","ray_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_name":"s"}',
            "2.61.0",
        ),
        ('{\n  "ray_version": "2.9.3",\n  "version": "1"\n}', "2.9.3"),
        ('{"ray_version" : "3.0.0.dev0", "version": "4"}', "3.0.0.dev0"),
    ],
)
def test_logs_only_the_version_string(content_regex, body, expected):
    assert extract_version(content_regex, body) == expected


@pytest.mark.parametrize(
    "body",
    [
        '{"version": "4", "ray_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
        '{"ray_version": ""}',
        '{"ray_version": 2}',
        '{"not_ray_version": "2.50.1"}',
        '{"database":"ok","version":"1.29.1"}',
        "<html><head><title>Unauthorized</title></head></html>",
        "",
    ],
)
def test_no_false_positive_match(content_regex, body):
    assert re.findall(content_regex, body) == []


def test_hostile_body_is_matched_quickly(content_regex):
    """A target controls the response, so a large body that never completes the
    pattern must not make the match slow."""
    body = '{"ray_version": "' + "a" * 200000
    start = time.perf_counter()
    assert content_regex.findall(body) == []
    assert time.perf_counter() - start < 1.0
