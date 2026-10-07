"""The agent runs under an init in every compose profile (GH-281, Decision 10; contract D1).

Issue #281, DevOps: "The agent service sets ``init: true`` in every compose profile, so
a killed conversion's grandchildren are reaped". Testing: "Compose validation shows
``init: true`` on the agent in every profile". Decision 10: ``init: true`` is set on
the ``agent`` service in docker-compose.yml; every overlay (local, prod, dev) inherits
it and none overrides it.

Static check, no Docker: each profile is docker-compose.yml plus one overlay
(every ``docker-compose.*.yml`` of the repository, so a new overlay is covered too),
merged the way compose merges a scalar service key (the overlay's value, when it has
one, replaces the base's). ``init`` must be the YAML boolean ``true`` (not the string).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

import pytest
import yaml

_REPO: Final = Path(__file__).resolve().parents[1]
_BASE: Final = "docker-compose.yml"
_OVERLAYS: Final = tuple(sorted(path.name for path in _REPO.glob("docker-compose.*.yml")))
_MISSING: Final = "<missing>"


def _compose(name: str) -> dict[str, Any]:
    loaded = yaml.safe_load((_REPO / name).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict), name
    return loaded


def _agent(name: str) -> dict[str, Any]:
    services = _compose(name).get("services") or {}
    agent = services.get("agent") or {}
    assert isinstance(agent, dict), name
    return agent


def _merged_init(overlay: str) -> object:
    """The agent's ``init`` in base + ``overlay`` (the overlay's value wins when set)."""
    base = _agent(_BASE)
    override = _agent(overlay)
    if "init" in override:
        return override["init"]
    return base.get("init", _MISSING)


def test_compose_init_base_agent_runs_under_an_init() -> None:
    """docker-compose.yml: ``services.agent.init`` is the boolean true."""
    assert _agent(_BASE).get("init", _MISSING) is True


@pytest.mark.parametrize("overlay", _OVERLAYS)
def test_compose_init_every_profile_keeps_the_agents_init(overlay: str) -> None:
    """Base + each overlay (local, prod, dev): the merged agent still has ``init: true``;
    an overlay that sets ``init`` sets it to true as well."""
    override = _agent(overlay).get("init", _MISSING)

    assert (_merged_init(overlay), override in (_MISSING, True)) == (True, True)


def test_compose_init_covers_the_three_shipped_overlays() -> None:
    """The profiles checked above include the laptop, production and dev overlays (the
    Makefile's ``COMPOSE_FILES``, ``PROD_COMPOSE_FILES`` and ``dev-db``)."""
    expected = {"docker-compose.local.yml", "docker-compose.prod.yml", "docker-compose.dev.yml"}

    assert (expected <= set(_OVERLAYS), [_merged_init(name) for name in sorted(expected)]) == (
        True,
        [True, True, True],
    )
