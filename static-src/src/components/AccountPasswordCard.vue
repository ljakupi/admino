<script setup lang="ts">
/**
 * My account: change password (issue #166). Renders the form and forwards
 * the attempt to the account store, which runs the client-side policy check
 * and never keeps a password in its state. A successful change already
 * ended every session server-side (including this one), so this card routes
 * to the login page itself.
 */
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, PASSWORD_RULE_KEYS } from '@/services/passwordPolicy';
import { useAccountStore } from '@/stores/account';
import { useToastStore } from '@/stores/toasts';
import { useI18n, type MessageKey } from '@/i18n';

const { t } = useI18n();
const router = useRouter();
const account = useAccountStore();
const toasts = useToastStore();

const currentPassword = ref('');
const newPassword = ref('');
const confirmPassword = ref('');
const errorKey = ref<MessageKey | null>(null);

function clearFields(): void {
  currentPassword.value = '';
  newPassword.value = '';
  confirmPassword.value = '';
}

async function handleSubmit(): Promise<void> {
  const email = account.account?.email ?? '';
  const result = await account.changePassword(currentPassword.value, newPassword.value, confirmPassword.value, email);
  clearFields();

  if (result.ok) {
    errorKey.value = null;
    toasts.add('success', t('account.toast.passwordChanged'));
    await router.replace('/login');
  } else {
    errorKey.value = result.messageKey;
  }
}
</script>

<template>
  <div class="section-head">
    <h2 class="section-title">{{ t('account.password.title') }}</h2>
    <p class="section-sub">{{ t('account.password.subtitle') }}</p>
  </div>

  <form class="s-card" @submit.prevent="handleSubmit">
    <ul class="password-rules">
      <li v-for="key in PASSWORD_RULE_KEYS" :key="key">
        {{ t(key, { min: PASSWORD_MIN_LENGTH, max: PASSWORD_MAX_LENGTH }) }}
      </li>
    </ul>

    <div class="s-row stack">
      <label class="row-label" for="account-password-current">{{ t('account.password.current') }}</label>
      <input
        id="account-password-current"
        v-model="currentPassword"
        class="s-input"
        type="password"
        autocomplete="current-password"
        :disabled="account.changingPassword"
      />
    </div>
    <div class="s-row stack">
      <label class="row-label" for="account-password-new">{{ t('account.password.new') }}</label>
      <input
        id="account-password-new"
        v-model="newPassword"
        class="s-input"
        type="password"
        autocomplete="new-password"
        :disabled="account.changingPassword"
      />
    </div>
    <div class="s-row stack">
      <label class="row-label" for="account-password-confirm">{{ t('account.password.confirm') }}</label>
      <input
        id="account-password-confirm"
        v-model="confirmPassword"
        class="s-input"
        type="password"
        autocomplete="new-password"
        :disabled="account.changingPassword"
      />
    </div>

    <div class="s-row stack">
      <p class="row-hint">{{ t('account.password.notice') }}</p>
      <p v-if="errorKey" class="s-error" role="alert">{{ t(errorKey) }}</p>
      <div class="account-save">
        <button class="s-btn primary" type="submit" :disabled="account.changingPassword">
          {{ t('account.password.submit') }}
        </button>
      </div>
    </div>
  </form>
</template>

<style scoped>
.password-rules {
  list-style: none;
  padding: 14px 20px 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 12.5px;
  color: var(--color-text-muted);
}

.account-save {
  display: flex;
  justify-content: flex-start;
}
</style>
