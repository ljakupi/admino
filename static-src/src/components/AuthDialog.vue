<script setup lang="ts">
import { ref } from 'vue';
import BaseButton from './BaseButton.vue';
import BaseInput from './BaseInput.vue';
import { useSettingsStore } from '@/stores/settings';

const settings = useSettingsStore();
const tokenInput = ref('');
const error = ref('');
const checking = ref(false);

const TOKEN_RE = /^[\x21-\x7E]{8,512}$/;

async function submit() {
  if (!tokenInput.value) {
    error.value = 'Token is required';
    return;
  }
  if (!TOKEN_RE.test(tokenInput.value)) {
    error.value = 'Token must be 8-512 printable ASCII characters';
    return;
  }
  // Validate the token against the backend before accepting
  checking.value = true;
  error.value = '';
  try {
    const res = await fetch('/api/message', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenInput.value}`,
      },
      body: JSON.stringify({ message: 'ping', session_id: 'auth-check' }),
    });
    if (res.status === 401) {
      error.value = 'Invalid token. Check and try again.';
      return;
    }
  } catch {
    // Network error — accept token anyway, will fail later with a clear message
  } finally {
    checking.value = false;
  }
  settings.setToken(tokenInput.value);
}

async function skip() {
  checking.value = true;
  error.value = '';
  try {
    // Try an API call without a token — if 401, token is required
    const res = await fetch('/api/message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: 'ping', session_id: 'auth-check' }),
    });
    if (res.status === 401) {
      error.value = 'This server requires a token. Skipping is not available.';
      return;
    }
  } catch {
    // Network error — let them skip, will show offline banner
  } finally {
    checking.value = false;
  }
  settings.skipAuth();
}
</script>

<template>
  <div class="auth-backdrop">
    <div class="auth-dialog">
      <div class="auth-logo">admino</div>
      <h2>Welcome</h2>
      <p class="caption">Enter your access token to connect, or skip if you're on a private network.</p>
      <form @submit.prevent="submit">
        <BaseInput
          v-model="tokenInput"
          label="Access Token"
          type="password"
          placeholder="Paste your token"
          :error="error"
        />
        <div class="auth-actions">
          <BaseButton variant="ghost" type="button" :disabled="checking" @click="skip">Skip</BaseButton>
          <BaseButton variant="primary" type="submit" :loading="checking">Connect</BaseButton>
        </div>
      </form>
    </div>
  </div>
</template>

<style scoped>
.auth-backdrop {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--color-bg);
  z-index: 1000;
}

.auth-dialog {
  width: 90%;
  max-width: 380px;
  background: var(--color-bg-surface);
  border-radius: var(--radius-card);
  padding: var(--space-8);
  box-shadow: var(--shadow-card);
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.auth-logo {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 28px;
  color: var(--color-primary);
  letter-spacing: -0.025em;
}

.auth-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-3);
  margin-top: var(--space-4);
}
</style>
