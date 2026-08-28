"""Tests pinning the committed out-of-the-box default files (issue #95).

Unlike tests/test_config.py, which validates config *behavior* using tmp_path
fixtures, this module asserts against the **committed default files** shipped
in the repository:

- ``config/config.yaml`` — the default application config.
- ``.env.example`` — the template developers copy to ``.env``.

The two files must tell one coherent story: a fresh clone defaults to the
**anthropic** provider (cloud) and therefore requires ``ANTHROPIC_API_KEY`` to
start, with the anthropic model pre-set. Local vLLM serving is coming soon.

Hermeticity: ``load_app_config`` and the ``LLMConfig`` validators consult a
number of environment variables (AUTH_TOKEN, ANTHROPIC_API_KEY, OPENAI_API_KEY,
LLM_PROVIDER, AUTH_MODE, LOG_LEVEL, AUDIT_LOG_PATH). A fixture clears all of
them so these tests are independent of the developer's shell environment.
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
def shipped_config(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> AppConfig:
    """Load the committed config/config.yaml with a clean env plus the required key.

    The shipped anthropic provider requires ANTHROPIC_API_KEY at load time, so it
    is set here (after clean_env clears it) to inspect the config's values.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-suite-key")
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
# Shipped config/config.yaml defaults
# ---------------------------------------------------------------------------


class TestShippedConfigDefaults:
    """The committed config.yaml must default to a working anthropic setup."""

    def test_shipped_config_defaults_to_anthropic_provider(self, shipped_config: AppConfig) -> None:
        """The shipped provider is 'anthropic' (cloud, the current default)."""
        assert shipped_config.llm.provider == "anthropic"

    def test_shipped_config_sets_anthropic_model(self, shipped_config: AppConfig) -> None:
        """A model ID is pre-set so a fresh clone only needs the API key."""
        assert isinstance(shipped_config.llm.anthropic_model, str)
        assert shipped_config.llm.anthropic_model != ""

    def test_shipped_config_requires_anthropic_api_key(self, clean_env: None) -> None:
        """Loading the shipped config with no ANTHROPIC_API_KEY fails clearly."""
        with pytest.raises(ValueError, match="Invalid application config"):
            load_app_config(SHIPPED_CONFIG_PATH)

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

    def test_shipped_egress_includes_anthropic_excludes_openai(
        self, shipped_config: AppConfig
    ) -> None:
        """The default provider's host is whitelisted; the opt-in one is not."""
        assert "api.anthropic.com" in shipped_config.egress.allowed_hosts
        assert "api.openai.com" not in shipped_config.egress.allowed_hosts


# ---------------------------------------------------------------------------
# Shipped .env.example coherence with config.yaml
# ---------------------------------------------------------------------------


class TestShippedEnvExample:
    """The committed .env.example must match the anthropic-first config story."""

    def test_env_example_does_not_override_auth_mode(self) -> None:
        """No active AUTH_MODE line, or it is 'vpn' — must not force 'token'."""
        env_text = SHIPPED_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
        auth_modes = _active_env_values(env_text, "AUTH_MODE")
        assert all(value == "vpn" for value in auth_modes)

    def test_env_example_provider_is_anthropic_or_unset(self) -> None:
        """Any active LLM_PROVIDER line must be 'anthropic' (the default)."""
        env_text = SHIPPED_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
        providers = _active_env_values(env_text, "LLM_PROVIDER")
        assert all(value == "anthropic" for value in providers)

    def test_env_example_has_anthropic_key_and_no_ollama_vars(self) -> None:
        """.env.example prompts for ANTHROPIC_API_KEY and carries no ollama vars."""
        env_text = SHIPPED_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
        # ANTHROPIC_API_KEY is present as an active (empty) line to fill in.
        assert _active_env_values(env_text, "ANTHROPIC_API_KEY") == [""]
        # No leftover Ollama configuration.
        assert "OLLAMA_BASE_URL" not in env_text
        assert "OLLAMA_MODEL" not in env_text
