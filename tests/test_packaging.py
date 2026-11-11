"""Static guards for the deployment artifacts: compose files, Helm chart, registry manifests.

These read the files as text or data. They do not start a container or run
``helm``; the chart's rendered output is checked by hand when it changes. What
they pin is the set of promises these files made and broke: a read-only
container that silently dropped its audit log, a registry entry describing an
image that exits at startup, a compose hint that made the file unparseable, and
a chart whose comments offered settings the templates never had.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from mcp_unifi import audit
from mcp_unifi.config import Settings

REPO_ROOT = Path(__file__).resolve().parent.parent
CHART = REPO_ROOT / "charts" / "mcp-unifi"
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.example.yml")

# The keys server.json already uses for an environment variable. The registry
# schema was not checked when this guard was written, so the file stays inside
# the vocabulary it already had instead of inventing fields.
SERVER_JSON_ENV_KEYS = {
    "name",
    "description",
    "isRequired",
    "isSecret",
    "default",
    "format",
    "choices",
}


def _server_json_env() -> dict[str, dict[str, Any]]:
    data = json.loads((REPO_ROOT / "server.json").read_text(encoding="utf-8"))
    return {e["name"]: e for e in data["packages"][0]["environmentVariables"]}


def _settings_env_names() -> set[str]:
    """Every environment variable the server reads: Settings fields, aliases, audit variables."""
    # MCP_UNIFI_MODULES_ENABLED is read straight from os.environ by the
    # dispatcher, not through Settings.
    names: set[str] = {
        audit.ENV_SINK,
        audit.ENV_PATH,
        audit.ENV_SYSLOG_ADDRESS,
        "MCP_UNIFI_MODULES_ENABLED",
    }
    for field_name, field in Settings.model_fields.items():
        names.add(field_name.upper())
        alias = field.validation_alias
        choices = getattr(alias, "choices", None)
        if choices:
            names.update(str(c).upper() for c in choices)
        elif isinstance(alias, str):
            names.add(alias.upper())
    return names


# ---------------------------------------------------------------------------
# server.json
# ---------------------------------------------------------------------------


def test_server_json_declares_the_auth_token_the_image_cannot_start_without() -> None:
    env = _server_json_env()
    entry = env["MCP_UNIFI_AUTH_TOKENS"]
    assert entry["isRequired"] is True
    assert entry["isSecret"] is True


def test_server_json_does_not_promise_an_out_of_the_box_image() -> None:
    env = _server_json_env()
    assert "out of the box" not in env["STUB_MODE"]["description"]
    assert "MCP_UNIFI_AUTH_TOKENS" in env["STUB_MODE"]["description"]


@pytest.mark.parametrize("name", ["MCP_UNIFI_READONLY", "UNIFI_API_KEY_FILE", "UNIFI_PINNED_CERT"])
def test_server_json_declares_the_safety_and_secret_file_variables(name: str) -> None:
    assert name in _server_json_env()


def test_server_json_stays_inside_its_existing_field_vocabulary() -> None:
    for name, entry in _server_json_env().items():
        assert set(entry) <= SERVER_JSON_ENV_KEYS, f"{name} uses a field the file never used"


def test_server_json_environment_names_are_variables_the_server_reads() -> None:
    known = _settings_env_names()
    unknown = sorted(set(_server_json_env()) - known)
    assert not unknown, f"server.json declares variables nothing reads: {unknown}"


# ---------------------------------------------------------------------------
# docker-compose
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fname", COMPOSE_FILES)
def test_compose_read_only_container_sends_audit_to_stdout(fname: str) -> None:
    compose = yaml.safe_load((REPO_ROOT / fname).read_text(encoding="utf-8"))
    svc = compose["services"]["mcp-unifi"]
    assert svc["read_only"] is True
    # A file under a read-only root is unwritable and the sink swallows the
    # failure, so the audit log must not default to one here.
    assert svc["environment"]["MCP_UNIFI_AUDIT_SINK"] == "stdout"
    assert "stdout" in audit.VALID_SINKS


@pytest.mark.parametrize("fname", COMPOSE_FILES)
def test_compose_service_has_exactly_one_environment_block_even_when_hints_are_uncommented(
    fname: str,
) -> None:
    """A hint the file tells the reader to uncomment must not add a second ``environment:`` key."""
    lines = (REPO_ROOT / fname).read_text(encoding="utf-8").splitlines()
    # Uncomment every hint line that is a YAML key or list item, as an operator would.
    uncommented = [re.sub(r"^(\s*)# (?=\S)", r"\1", line) for line in lines]
    env_keys = [ln for ln in uncommented if re.match(r"^    environment:\s*$", ln)]
    assert len(env_keys) == 1, f"{fname}: {len(env_keys)} environment keys after uncommenting"


# ---------------------------------------------------------------------------
# smithery.yaml
# ---------------------------------------------------------------------------


def test_smithery_stdio_command_keeps_stdin_open() -> None:
    smithery = yaml.safe_load((REPO_ROOT / "smithery.yaml").read_text(encoding="utf-8"))
    command = smithery["startCommand"]["commandFunction"]
    assert '"MCP_TRANSPORT=stdio"' in command
    # A stdio server exits at once when `docker run` has no -i and stdin is closed.
    assert '"run", "--rm", "-i"' in command


# ---------------------------------------------------------------------------
# Helm chart
# ---------------------------------------------------------------------------


def _values() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    return loaded


def test_chart_defaults_audit_to_stdout_because_the_root_filesystem_is_read_only() -> None:
    values = _values()
    assert values["securityContext"]["readOnlyRootFilesystem"] is True
    assert values["audit"]["sink"] == "stdout"
    assert values["audit"]["sink"] in audit.VALID_SINKS
    deployment = (CHART / "templates" / "deployment.yaml").read_text(encoding="utf-8")
    assert "MCP_UNIFI_AUDIT_SINK" in deployment


def test_chart_probes_follow_the_named_container_port() -> None:
    values = _values()
    for probe in ("livenessProbe", "readinessProbe"):
        # A number here crash-loops the pod the moment service.port changes.
        assert values[probe]["httpGet"]["port"] == "http"


def test_chart_memory_limit_clears_the_idle_footprint() -> None:
    limit = _values()["resources"]["limits"]["memory"]
    assert limit == "256Mi"


def test_chart_has_the_escape_hatches_its_comments_promise() -> None:
    values = _values()
    for key in ("extraEnv", "extraEnvFrom", "extraVolumes", "extraVolumeMounts"):
        assert values[key] == []
    deployment = (CHART / "templates" / "deployment.yaml").read_text(encoding="utf-8")
    for key in ("extraEnv", "extraEnvFrom", "extraVolumes", "extraVolumeMounts"):
        assert f".Values.{key}" in deployment


def test_chart_does_not_claim_a_metrics_endpoint() -> None:
    text = (CHART / "values.yaml").read_text(encoding="utf-8")
    assert "prometheus.io" not in text
    assert "/metrics endpoint is exposed" not in text


def test_chart_templates_only_reference_values_that_exist() -> None:
    values = _values()
    missing: list[str] = []
    for template in sorted((CHART / "templates").glob("*")):
        for ref in re.findall(r"\.Values\.([A-Za-z0-9_.]+)", template.read_text(encoding="utf-8")):
            node: Any = values
            for part in ref.split("."):
                if not isinstance(node, dict) or part not in node:
                    missing.append(f"{template.name}: .Values.{ref}")
                    break
                node = node[part]
    assert not missing, f"templates read values that values.yaml does not define: {missing}"


def test_chart_env_names_are_variables_the_server_reads() -> None:
    known = _settings_env_names()
    deployment = (CHART / "templates" / "deployment.yaml").read_text(encoding="utf-8")
    names = set(re.findall(r"- name: ([A-Z][A-Z0-9_]+)\n", deployment))
    assert names, "no env names found in deployment.yaml"
    assert names - known == set()
