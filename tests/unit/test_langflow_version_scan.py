"""Behavioural tests for the langflow_version_scan module.

These tests load the shipped module definition and exercise its version
detection regex exactly the way the HTTP engine does (``re.findall`` on the
response body, then joined into the log line). A Langflow server answers ``/api/v1/version`` without signing in, with a JSON object that names the package and its version. Like the other
``*_version_scan`` modules this is a fingerprint only: it logs the version and
makes no claim about whether the build is vulnerable.
"""

import re
import time
from pathlib import Path

import pytest
import yaml

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "nettacker"
    / "modules"
    / "scan"
    / "langflow_version.yaml"
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
    assert info["name"] == "langflow_version_scan"
    assert info["severity"] == 3
    assert "scan" in info["profiles"]
    assert "langflow" in info["profiles"]
    assert "info_severity" in info["profiles"]


def test_targets_expected_endpoint_and_ports(step):
    fuzzer = step["url"]["nettacker_fuzzer"]
    assert fuzzer["input_format"].endswith("/api/v1/version")
    data = fuzzer["data"]
    assert data["schema"] == ["http", "https"]
    assert set(data["ports"]) == {80, 443, 7860}


def test_requires_http_200_and_logs_the_capture(step):
    conditions = step["response"]["conditions"]
    assert conditions["status_code"]["regex"] == "200"
    assert step["response"]["condition_type"] == "and"
    assert step["response"]["log"] == "response_dependent['content']"


@pytest.mark.parametrize(
    "body, expected",
    [
        ('{"version":"1.6.0","main_version":"1.6.0","package":"Langflow"}', "1.6.0"),
        ('{"version": "1.0.19", "package": "Langflow"}', "1.0.19"),
        ('{"package": "Langflow Base", "version": "0.6.0", "main_version": "1.6.0"}', "0.6.0"),
        (
            '{\n  "version": "1.12.10",\n  "main_version": "1.12.10",\n  "package": "Langflow"\n}',
            "1.12.10",
        ),
    ],
)
def test_logs_only_the_version_string(content_regex, body, expected):
    assert extract_version(content_regex, body) == expected


@pytest.mark.parametrize(
    "body",
    [
        '{"version":"1.6.0","package":"SomethingElse"}',
        '{"version":"1.6.0"}',
        '{"package":"Langflow"}',
        '{"package":"Langflow","version":""}',
        '{"main_version":"1.6.0","package":"Langflow"}',
        '{"package":"Langflow","nested":{"version":"9.9.9"}}',
        '{"database":"ok","version":"1.29.1"}',
        "<html><head><title>Langflow</title></head></html>",
        "",
    ],
)
def test_no_false_positive_match(content_regex, body):
    assert re.findall(content_regex, body) == []


def test_hostile_body_is_matched_quickly(content_regex):
    """A target controls the response, so a large body that never completes the
    pattern must not make the match slow."""
    body = '{"package": "Langflow", "version": "' + "a" * 200000
    start = time.perf_counter()
    assert content_regex.findall(body) == []
    assert time.perf_counter() - start < 1.0
