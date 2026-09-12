"""Tests pinning the committed out-of-the-box default files (issue #95).

Unlike tests/test_config.py, which validates config *behavior* using tmp_path
fixtures, this module asserts against the **committed default files** shipped
in the repository:

- ``config/config.yaml`` — the default application config.
- ``.env.example`` — the template developers copy to ``.env``.

The two files must tell one coherent story: a fresh clone defaults to the
**vLLM** provider (local) and therefore boots with **no API key**. Claude
(anthropic) and OpenAI stay opt-in — their model IDs stay pre-set so switching
to a cloud provider only needs the API key, not a config edit.

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
def shipped_config(clean_env: None) -> AppConfig:
    """Load the committed config/config.yaml under a fully clean env.

    The shipped vLLM provider needs no API key at load time, so the config
    loads with every relevant env var cleared (see clean_env).
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


# ---------------------------------------------------------------------------
# Shipped config/config.yaml defaults
# ---------------------------------------------------------------------------


class TestShippedConfigDefaults:
    """The committed config.yaml must default to a working, keyless vLLM setup."""

    def test_shipped_config_defaults_to_vllm_provider(self, shipped_config: AppConfig) -> None:
        """The shipped provider is 'vllm' (local, the current default)."""
        assert shipped_config.llm.provider == "vllm"

    def test_shipped_config_sets_anthropic_model(self, shipped_config: AppConfig) -> None:
        """A model ID is pre-set so switching to Claude only needs the API key."""
        assert isinstance(shipped_config.llm.anthropic_model, str)
        assert shipped_config.llm.anthropic_model != ""

    def test_shipped_config_boots_without_api_key(self, clean_env: None) -> None:
        """Loading the shipped config with no API key succeeds and stays on vllm."""
        config = load_app_config(SHIPPED_CONFIG_PATH)
        assert config.llm.provider == "vllm"

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
        """Anthropic's host stays whitelisted for the interim cloud opt-in; OpenAI's is not.

        The default is now vllm (local), but api.anthropic.com remains in the
        egress list so switching to Claude works without an egress edit, while
        api.openai.com stays out until the user opts in.
        """
        assert "api.anthropic.com" in shipped_config.egress.allowed_hosts
        assert "api.openai.com" not in shipped_config.egress.allowed_hosts


# ---------------------------------------------------------------------------
# Shipped vLLM defaults (issue #134)
# ---------------------------------------------------------------------------


class TestShippedVLLMDefaults:
    """The committed config.yaml pins the first-class vLLM provider defaults."""

    def test_shipped_vllm_model_is_mlx_gemma(self, shipped_config: AppConfig) -> None:
        """The shipped vllm_model is the MLX Gemma id."""
        assert shipped_config.llm.vllm_model == "mlx-community/gemma-4-12B-it-4bit"

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
    """The committed .env.example must match the vLLM-default config story."""

    def test_env_example_does_not_override_auth_mode(self) -> None:
        """No active AUTH_MODE line, or it is 'vpn' — must not force 'token'."""
        env_text = SHIPPED_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
        auth_modes = _active_env_values(env_text, "AUTH_MODE")
        assert all(value == "vpn" for value in auth_modes)

    def test_env_example_provider_unset_or_vllm(self) -> None:
        """Any active LLM_PROVIDER line must be 'vllm'.

        LLM_PROVIDER is normally commented out so config.yaml's vllm default
        wins; if it is ever active it must not override away from vllm.
        """
        env_text = SHIPPED_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
        providers = _active_env_values(env_text, "LLM_PROVIDER")
        assert all(value == "vllm" for value in providers)

    def test_env_example_anthropic_key_is_optin(self) -> None:
        """.env.example documents ANTHROPIC_API_KEY as opt-in (commented out).

        With the vllm default (boots without any key), no cloud API key ships as
        an active line — ANTHROPIC_API_KEY is documented but commented out, like
        OPENAI_API_KEY, so a fresh clone starts with no secrets exported.
        """
        env_text = SHIPPED_ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
        # The key is documented for the anthropic cloud opt-in...
        assert "ANTHROPIC_API_KEY" in env_text
        # ...but must NOT be an active line — no empty secret is exported by default.
        assert _active_env_values(env_text, "ANTHROPIC_API_KEY") == []
