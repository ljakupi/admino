"""Tests pinning the committed out-of-the-box default files (issue #95).

Unlike tests/test_config.py, which validates config *behavior* using tmp_path
fixtures, this module asserts against the **committed default files** shipped
in the repository:

- ``config/config.yaml`` — the default application config.
- ``.env.example`` — the template developers copy to ``.env``.

The acceptance criteria for GH-95 require these two files to tell one coherent
story: a fresh clone must run locally against Ollama with zero edits and zero
API keys, while switching to a proprietary provider requires only an API key,
a provider change, and an egress entry — never a model edit.

Hermeticity: ``load_app_config`` and the ``LLMConfig`` validators consult a
number of environment variables (AUTH_TOKEN, ANTHROPIC_API_KEY, OPENAI_API_KEY,
LLM_PROVIDER, OLLAMA_BASE_URL, OLLAMA_MODEL, AUTH_MODE, LOG_LEVEL,
AUDIT_LOG_PATH). A fixture clears all of them so these tests are independent of
the developer's shell environment or a local ``.env``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from admino.config import AppConfig, load_app_config

# The committed default files, located relative to this test file.
REPO_ROOT = Path(__file__).resolve().parent.parent
SHIPPED_CONFIG_PATH = REPO_ROOT / "config" / "config.yaml"
SHIPPED_ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"

# Env vars that load_app_config / LLMConfig validators read. Cleared per test
# so results reflect only the committed files, not the developer's environment.
_ENV_VARS_TO_CLEAR = (
    "AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "LLM_PROVIDER",
    "OLLAMA_BASE_URL",
    "OLLAMA_MODEL",
    "AUTH_MODE",
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
    """Load the committed config/config.yaml with a clean environment."""
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


# ---------------------------------------------------------------------------
# 1-6. Shipped config/config.yaml defaults
# ---------------------------------------------------------------------------


class TestShippedConfigDefaults:
    """The committed config.yaml must default to a working, local Ollama setup."""

    def test_shipped_config_defaults_to_ollama_provider(self, shipped_config: AppConfig) -> None:
        """The shipped provider is 'ollama' (local, zero external calls)."""
        assert shipped_config.llm.provider == "ollama"

    def test_shipped_config_has_working_ollama_defaults(self, shipped_config: AppConfig) -> None:
        """Shipped Ollama URL is localhost and a model is set — runs with zero edits."""
        assert shipped_config.llm.ollama_url == "http://localhost:11434"
        assert isinstance(shipped_config.llm.model, str)
        assert shipped_config.llm.model != ""

    def test_shipped_config_loads_without_any_api_keys(self, clean_env: None) -> None:
        """Loading the shipped config with no proprietary API keys raises no error."""
        config = load_app_config(SHIPPED_CONFIG_PATH)
        assert isinstance(config, AppConfig)

    def test_shipped_config_keeps_proprietary_models_configured(
        self, shipped_config: AppConfig
    ) -> None:
        """Anthropic/OpenAI model IDs stay set so switching needs no model edit."""
        assert isinstance(shipped_config.llm.anthropic_model, str)
        assert shipped_config.llm.anthropic_model != ""
        assert isinstance(shipped_config.llm.openai_model, str)
        assert shipped_config.llm.openai_model != ""

    def test_shipped_config_auth_mode_is_vpn(self, shipped_config: AppConfig) -> None:
        """Shipped auth mode is 'vpn' — the localhost-first default."""
        assert shipped_config.auth.mode == "vpn"

    def test_shipped_egress_excludes_proprietary_llm_hosts(self, shipped_config: AppConfig) -> None:
        """Proprietary LLM hosts are not whitelisted by default (matches ollama)."""
        assert "api.anthropic.com" not in shipped_config.egress.allowed_hosts
        assert "api.openai.com" not in shipped_config.egress.allowed_hosts


# ---------------------------------------------------------------------------
# 7-9. Shipped .env.example coherence with config.yaml
# ---------------------------------------------------------------------------


class TestShippedEnvExample:
    """The committed .env.example must not silently override the local defaults."""

    def test_env_example_does_not_override_auth_mode(self) -> None:
        """No active AUTH_MODE line, or it is 'vpn' — must not force 'token'."""
        env_text = SHIPPED_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
        auth_modes = _active_env_values(env_text, "AUTH_MODE")
        assert all(value == "vpn" for value in auth_modes)

    def test_env_example_does_not_override_provider(self) -> None:
        """No active LLM_PROVIDER line, or it is 'ollama'."""
        env_text = SHIPPED_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
        providers = _active_env_values(env_text, "LLM_PROVIDER")
        assert all(value == "ollama" for value in providers)

    def test_env_example_ollama_model_matches_shipped_config(
        self, shipped_config: AppConfig
    ) -> None:
        """The active OLLAMA_MODEL in .env.example equals config.yaml's model.

        One coherent model recommendation across both files: the value a user
        would export must match what the config ships with.
        """
        env_text = SHIPPED_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
        models = _active_env_values(env_text, "OLLAMA_MODEL")
        assert models == [shipped_config.llm.model]
