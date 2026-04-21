import { defineStore } from 'pinia';
import { ref, watch } from 'vue';

export type LLMProvider = 'ollama' | 'claude' | 'openai';

const TOKEN_KEY = 'admino_auth_token';
const SESSION_KEY = 'admino_session_id';
const PROVIDER_KEY = 'admino_provider';
const MODEL_KEY = 'admino_model';
const OLLAMA_URL_KEY = 'admino_ollama_url';

const TOKEN_RE = /^[\x21-\x7E]{8,512}$/;
const SESSION_RE = /^[a-zA-Z0-9_-]{1,64}$/;

function generateSessionId(): string {
  const ts = Date.now().toString(36);
  const rand = Array.from(crypto.getRandomValues(new Uint8Array(8)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `s-${ts}-${rand}`;
}

export const useSettingsStore = defineStore('settings', () => {
  // Auth token
  const token = ref<string | null>(loadToken());
  const needsAuth = ref(!token.value);

  function loadToken(): string | null {
    const stored = localStorage.getItem(TOKEN_KEY);
    if (stored && TOKEN_RE.test(stored)) return stored;
    return null;
  }

  function setToken(value: string | null) {
    if (value && TOKEN_RE.test(value)) {
      localStorage.setItem(TOKEN_KEY, value);
      token.value = value;
      needsAuth.value = false;
    } else if (value === null) {
      localStorage.removeItem(TOKEN_KEY);
      token.value = null;
      needsAuth.value = false;
    }
  }

  function skipAuth() {
    localStorage.removeItem(TOKEN_KEY);
    token.value = null;
    needsAuth.value = false;
  }

  // Session ID
  const sessionId = ref(loadSessionId());

  function loadSessionId(): string {
    const stored = localStorage.getItem(SESSION_KEY);
    if (stored && SESSION_RE.test(stored)) return stored;
    const fresh = generateSessionId();
    localStorage.setItem(SESSION_KEY, fresh);
    return fresh;
  }

  function newSession() {
    const fresh = generateSessionId();
    localStorage.setItem(SESSION_KEY, fresh);
    sessionId.value = fresh;
  }

  // LLM provider settings
  const provider = ref<LLMProvider>(
    (localStorage.getItem(PROVIDER_KEY) as LLMProvider) || 'ollama',
  );
  const model = ref(localStorage.getItem(MODEL_KEY) || '');
  const ollamaUrl = ref(localStorage.getItem(OLLAMA_URL_KEY) || 'http://localhost:11434');

  watch(provider, (v) => localStorage.setItem(PROVIDER_KEY, v));
  watch(model, (v) => localStorage.setItem(MODEL_KEY, v));
  watch(ollamaUrl, (v) => localStorage.setItem(OLLAMA_URL_KEY, v));

  return {
    token, needsAuth, setToken, skipAuth,
    sessionId, newSession,
    provider, model, ollamaUrl,
  };
});
