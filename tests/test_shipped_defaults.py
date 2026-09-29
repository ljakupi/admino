"""Tests pinning the committed out-of-the-box default files (issues #95, #134, #142, #143).

Unlike tests/test_config.py, which validates config *behavior* using tmp_path
fixtures, this module asserts against the **committed default files** shipped
in the repository:

- ``config/config.yaml`` — the default application config.
- ``.env.example`` — the template developers copy to ``.env``.
- ``pyproject.toml`` — the package dependencies.

The files must tell one coherent story (GH-142): a fresh clone defaults to the
**Infomaniak** provider (Swiss-hosted, queries neither recorded nor used for
training) and still **boots with no INFOMANIAK_API_TOKEN** — chat then explains
what to set. ``api.infomaniak.com`` is on the egress whitelist. The local vLLM
model stays available as an opt-in with its defaults pinned, and Claude
(anthropic) / OpenAI stay opt-in with their model IDs pre-set. Because the
default provider talks through the OpenAI SDK, ``openai`` is a core dependency.

GH-149 removes the old auth: the shipped config.yaml has no ``auth`` section
(and no AUTH_TOKEN note), ``.env.example`` has no AUTH_TOKEN / AUTH_MODE line
and documents ``COOKIE_SECURE`` (the session cookie's Secure flag, on by
default), and the shipped config keeps ``server.cookie_secure`` on.

GH-156 (TLS reverse proxy): the shipped config.yaml sets
``server.trusted_proxies`` to an empty list (trust nobody; the production
compose overlay sets ADMINO_TRUSTED_PROXIES), and ``.env.example`` documents
``ADMINO_DOMAIN`` (the production profile's public hostname) and
``ADMINO_TRUSTED_PROXIES``, and describes ``COOKIE_SECURE=false`` as
development-only.

Hermeticity: ``load_app_config`` and the ``LLMConfig`` validators consult a
number of environment variables (provider keys/tokens, LLM_PROVIDER, VLLM_*
overrides, COOKIE_SECURE, ADMINO_PUBLIC_URL, ADMINO_TRUSTED_PROXIES, LOG_LEVEL,
AUDIT_LOG_PATH). A fixture clears all of them so these tests are independent of
the developer's shell environment.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

from admino.config import AppConfig, load_app_config

# The committed default files, located relative to this test file.
REPO_ROOT = Path(__file__).resolve().parent.parent
SHIPPED_CONFIG_PATH = REPO_ROOT / "config" / "config.yaml"
SHIPPED_ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

_INFOMANIAK_DEFAULT_MODEL = "Qwen/Qwen3.5-397B-A17B-FP8"

# Env vars that load_app_config / LLMConfig validators read. Cleared per test
# so results reflect only the committed files, not the developer's environment.
_ENV_VARS_TO_CLEAR = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "INFOMANIAK_API_TOKEN",
    "INFOMANIAK_PRODUCT_ID",
    "LLM_PROVIDER",
    "VLLM_MODEL",
    "VLLM_BASE_URL",
    "VLLM_MAX_MODEL_LEN",
    "COOKIE_SECURE",
    "ADMINO_PUBLIC_URL",
    "ADMINO_TRUSTED_PROXIES",
    "LOG_LEVEL",
    "AUDIT_LOG_PATH",
)


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove all env vars that could override the shipped config values."""
    for name in _ENV_VARS_TO_CLEAR:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def shipped_config(clean_env: None) -> AppConfig:
    """Load the committed config/config.yaml under a fully clean env.

    The shipped Infomaniak provider boots without INFOMANIAK_API_TOKEN (a
    warning is logged and chat explains), so the config loads with every
    relevant env var cleared (see clean_env).
    """
    return load_app_config(SHIPPED_CONFIG_PATH)


def _active_env_values(env_text: str, key: str) -> list[str]:
    """Return the values of active (uncommented) ``KEY=`` lines in a .env file.

    Blank lines and comment lines (starting with ``#``) are ignored. Matching
    is done on the ``KEY=`` prefix after stripping surrounding whitespace.
    """
    values: list[str] = []
    prefix = f"{key}="
    for raw_line in env_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(prefix):
            values.append(line[len(prefix) :].strip())
    return values


def _paragraphs_mentioning(env_text: str, key: str) -> list[str]:
    """Return the blank-line separated blocks of a .env file that contain ``KEY=``.

    A block is the comment paragraph around a variable, so it holds the
    variable's own documentation (active or commented-out line alike).
    """
    pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\s*=", re.MULTILINE)
    return [block for block in re.split(r"\n\s*\n", env_text) if pattern.search(block)]


def _requirement_name(requirement: str) -> str:
    """Return the normalised distribution name of a PEP 508 requirement string."""
    return re.split(r"[\s\[<>=!~;@(]", requirement.strip(), maxsplit=1)[0].lower()


def _pyproject() -> dict[str, Any]:
    """Parse the committed pyproject.toml."""
    with PYPROJECT_PATH.open("rb") as handle:
        return tomllib.load(handle)


# ---------------------------------------------------------------------------
# Shipped config/config.yaml defaults
# ---------------------------------------------------------------------------


class TestShippedConfigDefaults:
    """The committed config.yaml defaults to Infomaniak and boots without a token."""

    def test_shipped_config_defaults_to_infomaniak_provider(
        self, shipped_config: AppConfig
    ) -> None:
        """The shipped provider is 'infomaniak' (GH-142)."""
        assert shipped_config.llm.provider == "infomaniak"

    def test_shipped_config_sets_infomaniak_model(self, shipped_config: AppConfig) -> None:
        """The shipped infomaniak_model is Qwen/Qwen3.5-397B-A17B-FP8."""
        assert shipped_config.llm.infomaniak_model == _INFOMANIAK_DEFAULT_MODEL

    def test_shipped_config_active_model_is_infomaniak_model(
        self, shipped_config: AppConfig
    ) -> None:
        """The active model of the shipped config is the Infomaniak model."""
        assert shipped_config.llm.active_model_name == _INFOMANIAK_DEFAULT_MODEL

    def test_shipped_config_boots_without_infomaniak_token(self, clean_env: None) -> None:
        """Loading the shipped config with no INFOMANIAK_API_TOKEN succeeds and stays on it."""
        config = load_app_config(SHIPPED_CONFIG_PATH)
        assert config.llm.provider == "infomaniak"

    def test_shipped_config_sets_anthropic_model(self, shipped_config: AppConfig) -> None:
        """A model ID is pre-set so switching to Claude only needs the API key."""
        assert isinstance(shipped_config.llm.anthropic_model, str)
        assert shipped_config.llm.anthropic_model != ""

    def test_shipped_config_keeps_proprietary_models_configured(
        self, shipped_config: AppConfig
    ) -> None:
        """Anthropic/OpenAI model IDs stay set so switching needs no model edit."""
        assert isinstance(shipped_config.llm.anthropic_model, str)
        assert shipped_config.llm.anthropic_model != ""
        assert isinstance(shipped_config.llm.openai_model, str)
        assert shipped_config.llm.openai_model != ""

    def test_shipped_config_yaml_has_no_auth_section(self) -> None:
        """GH-149: auth.mode is gone, so config.yaml ships no auth section."""
        raw = yaml.safe_load(SHIPPED_CONFIG_PATH.read_text(encoding="utf-8"))
        assert isinstance(raw, dict)
        assert "auth" not in raw

    def test_shipped_config_yaml_does_not_mention_auth_token(self) -> None:
        """No stale AUTH_TOKEN note is left in the shipped config.yaml."""
        assert "AUTH_TOKEN" not in SHIPPED_CONFIG_PATH.read_text(encoding="utf-8")

    def test_shipped_config_cookie_secure_is_on(self, shipped_config: AppConfig) -> None:
        """The shipped config keeps the session cookie's Secure flag on."""
        assert shipped_config.server.cookie_secure is True

    def test_shipped_config_public_url_is_the_local_default(
        self, shipped_config: AppConfig
    ) -> None:
        """GH-151: laptop-first, reset links point at http://localhost:8000 unless a
        deployment sets ADMINO_PUBLIC_URL."""
        assert shipped_config.server.public_url == "http://localhost:8000"  # type: ignore[attr-defined]

    def test_shipped_config_yaml_sets_empty_trusted_proxies(self) -> None:
        """GH-156: config.yaml states server.trusted_proxies as an empty list (trust
        nobody); the production compose overlay sets ADMINO_TRUSTED_PROXIES."""
        raw = yaml.safe_load(SHIPPED_CONFIG_PATH.read_text(encoding="utf-8"))
        assert isinstance(raw, dict)
        assert isinstance(raw.get("server"), dict)
        assert "trusted_proxies" in raw["server"]
        assert raw["server"]["trusted_proxies"] == []

    def test_shipped_config_trusts_no_proxy(self, shipped_config: AppConfig) -> None:
        """GH-156: loaded, the shipped config trusts no proxy's forwarded headers."""
        assert shipped_config.server.trusted_proxies == []

    def test_shipped_egress_includes_infomaniak(self, shipped_config: AppConfig) -> None:
        """The default provider's API host is whitelisted (GH-142)."""
        assert "api.infomaniak.com" in shipped_config.egress.allowed_hosts

    def test_shipped_egress_includes_anthropic_excludes_openai(
        self, shipped_config: AppConfig
    ) -> None:
        """Anthropic's host stays whitelisted for the cloud opt-in; OpenAI's is not.

        api.anthropic.com remains in the egress list so switching to Claude
        works without an egress edit, while api.openai.com stays out until the
        user opts in.
        """
        assert "api.anthropic.com" in shipped_config.egress.allowed_hosts
        assert "api.openai.com" not in shipped_config.egress.allowed_hosts


# ---------------------------------------------------------------------------
# Shipped config/config.yaml has no local files tool (GH-143)
# ---------------------------------------------------------------------------


class TestShippedConfigHasNoFilesTool:
    """The local files tool is removed, so the committed config.yaml drops its section.

    Parsed as raw YAML: AppConfig would silently ignore a leftover section, so
    loading it through Pydantic cannot prove the section is gone.
    """

    @pytest.fixture()
    def raw_config(self) -> dict[str, Any]:
        """The committed config.yaml parsed as a plain mapping."""
        parsed = yaml.safe_load(SHIPPED_CONFIG_PATH.read_text(encoding="utf-8"))
        assert isinstance(parsed, dict)
        return parsed

    def test_shipped_config_has_no_files_section(self, raw_config: dict[str, Any]) -> None:
        """No top-level 'files' key in the shipped config.yaml."""
        assert "files" not in raw_config

    def test_shipped_config_does_not_expose_documents_dir(self) -> None:
        """No active config line points the agent at /app/documents."""
        active_lines = [
            line
            for line in SHIPPED_CONFIG_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert not any("/app/documents" in line for line in active_lines)


class TestShippedFilesHaveNoAuditLog:
    """GH-147: the NDJSON audit log is gone from the committed config and .env template.

    Parsed as raw YAML: AppConfig ignores a leftover section, so loading it
    through Pydantic cannot prove the section is gone.
    """

    def test_shipped_config_has_no_paths_section(self) -> None:
        """No top-level 'paths' key (its only entry was the audit log path)."""
        parsed = yaml.safe_load(SHIPPED_CONFIG_PATH.read_text(encoding="utf-8"))
        assert isinstance(parsed, dict)
        assert "paths" not in parsed

    def test_shipped_config_mentions_no_ndjson_audit_log(self) -> None:
        text = SHIPPED_CONFIG_PATH.read_text(encoding="utf-8")
        assert "audit_log" not in text
        assert "ndjson" not in text.lower()

    def test_env_example_has_no_audit_log_path(self) -> None:
        text = SHIPPED_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
        assert "AUDIT_LOG_PATH" not in text
        assert "ndjson" not in text.lower()


# ---------------------------------------------------------------------------
# Shipped vLLM defaults (issue #134) — vLLM is now the optional local model
# ---------------------------------------------------------------------------


class TestShippedVLLMDefaults:
    """The committed config.yaml still pins the opt-in vLLM provider defaults."""

    def test_shipped_vllm_model_is_qwen(self, shipped_config: AppConfig) -> None:
        """The shipped vllm_model is the Qwen id."""
        assert shipped_config.llm.vllm_model == "Qwen/Qwen3-4B-Instruct-2507"

    def test_shipped_vllm_base_url_is_http_url(self, shipped_config: AppConfig) -> None:
        """The shipped vllm_base_url is a non-empty http(s) URL."""
        base_url = shipped_config.llm.vllm_base_url
        assert isinstance(base_url, str)
        assert base_url != ""
        assert base_url.startswith(("http://", "https://"))

    def test_shipped_vllm_max_model_len_is_32768(self, shipped_config: AppConfig) -> None:
        """The shipped vllm_max_model_len is 32768."""
        assert shipped_config.llm.vllm_max_model_len == 32768


# ---------------------------------------------------------------------------
# Shipped .env.example coherence with config.yaml
# ---------------------------------------------------------------------------


class TestShippedEnvExample:
    """The committed .env.example must match the Infomaniak-default config story."""

    @pytest.fixture()
    def env_text(self) -> str:
        """The committed .env.example."""
        return SHIPPED_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")

    @pytest.mark.parametrize("removed", ["AUTH_TOKEN", "AUTH_MODE"])
    def test_env_example_has_no_removed_auth_variable(self, env_text: str, removed: str) -> None:
        """GH-149: no AUTH_TOKEN / AUTH_MODE line, active or commented out."""
        pattern = re.compile(rf"^\s*#?\s*{removed}\s*=", re.MULTILINE)
        assert pattern.search(env_text) is None

    def test_env_example_documents_admino_public_url(self, env_text: str) -> None:
        """GH-151: production deployments set ADMINO_PUBLIC_URL (the base of reset links),
        and .env.example says so."""
        assert re.search(r"^\s*#?\s*ADMINO_PUBLIC_URL\s*=", env_text, re.MULTILINE) is not None

    def test_env_example_documents_cookie_secure_without_disabling_it(self, env_text: str) -> None:
        """COOKIE_SECURE is documented, and no active line turns the Secure flag off."""
        assert "COOKIE_SECURE" in env_text
        values = _active_env_values(env_text, "COOKIE_SECURE")
        assert all(value.lower() in {"true", "1", "yes", "on"} for value in values)

    @pytest.mark.parametrize("variable", ["ADMINO_DOMAIN", "ADMINO_TRUSTED_PROXIES"])
    def test_env_example_documents_production_proxy_variable(
        self, env_text: str, variable: str
    ) -> None:
        """GH-156: the production profile's public hostname (ADMINO_DOMAIN) and the
        trusted proxy list (ADMINO_TRUSTED_PROXIES) are documented, active or commented."""
        pattern = re.compile(rf"^\s*#?\s*{variable}\s*=", re.MULTILINE)
        assert pattern.search(env_text) is not None

    def test_env_example_describes_insecure_cookie_as_dev_only(self, env_text: str) -> None:
        """GH-156: COOKIE_SECURE=false is described as a development-only setting."""
        paragraphs = _paragraphs_mentioning(env_text, "COOKIE_SECURE")
        assert paragraphs, "COOKIE_SECURE is not documented"
        # "dev", "dev-only" or "development" ("device" doesn't count).
        dev_only = re.compile(r"\b(?:dev|development)\b", re.IGNORECASE)
        assert any(dev_only.search(block) for block in paragraphs)

    def test_env_example_provider_unset_or_infomaniak(self, env_text: str) -> None:
        """Any active LLM_PROVIDER line must be 'infomaniak'.

        LLM_PROVIDER is normally commented out so config.yaml's infomaniak
        default wins; if it is ever active it must not override away from it.
        """
        providers = _active_env_values(env_text, "LLM_PROVIDER")
        assert all(value == "infomaniak" for value in providers)

    def test_env_example_documents_infomaniak_api_token(self, env_text: str) -> None:
        """INFOMANIAK_API_TOKEN is documented, and no real token value ships with it."""
        assert "INFOMANIAK_API_TOKEN" in env_text
        assert all(value == "" for value in _active_env_values(env_text, "INFOMANIAK_API_TOKEN"))

    def test_env_example_documents_ai_tools_scope(self, env_text: str) -> None:
        """The token's required 'ai-tools' scope is documented."""
        assert "ai-tools" in env_text

    def test_env_example_documents_infomaniak_product_id(self, env_text: str) -> None:
        """INFOMANIAK_PRODUCT_ID is documented (optional, auto-discovered)."""
        assert "INFOMANIAK_PRODUCT_ID" in env_text

    def test_env_example_anthropic_key_is_optin(self, env_text: str) -> None:
        """.env.example documents ANTHROPIC_API_KEY as opt-in (commented out).

        No cloud API key ships as an active line — ANTHROPIC_API_KEY is
        documented but commented out, like OPENAI_API_KEY, so a fresh clone
        starts with no secrets exported.
        """
        # The key is documented for the anthropic cloud opt-in...
        assert "ANTHROPIC_API_KEY" in env_text
        # ...but must NOT be an active line — no empty secret is exported by default.
        assert _active_env_values(env_text, "ANTHROPIC_API_KEY") == []


# ---------------------------------------------------------------------------
# pyproject.toml — openai is a core dependency (GH-142)
# ---------------------------------------------------------------------------


class TestShippedDependencies:
    """The default provider needs the OpenAI SDK, so it is no longer optional."""

    def test_openai_is_a_core_dependency(self) -> None:
        """'openai' is listed in [project].dependencies."""
        dependencies = _pyproject()["project"]["dependencies"]
        assert "openai" in {_requirement_name(dep) for dep in dependencies}

    def test_openai_optional_extra_removed(self) -> None:
        """There is no standalone 'openai' optional extra any more."""
        optional = _pyproject()["project"].get("optional-dependencies", {})
        assert "openai" not in optional
