<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import AuthCard from '@/components/AuthCard.vue';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import { confirmReset } from '@/services/authFlows';
import { consumeLinkToken } from '@/services/linkToken';
import {
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  PASSWORD_RULE_KEYS,
  checkNewPassword,
  issueMessageKey,
} from '@/services/passwordPolicy';
import { useToastStore } from '@/stores/toasts';
import { t } from '@/i18n';

const router = useRouter();
const toasts = useToastStore();

// Read once, on setup: strips the token from the address bar and history
// immediately, whether it turns out valid or not (window.history.state is
// preserved so vue-router's own navigation state survives the rewrite).
const token = consumeLinkToken(window.location, {
  replaceState: (_data, _unused, url) => window.history.replaceState(window.history.state, '', url),
});

const password = ref('');
const confirm = ref('');
const submitting = ref(false);
const errorText = ref('');

async function onSubmit(): Promise<void> {
  if (submitting.value || !token) return;

  const issues = checkNewPassword(password.value, confirm.value, '');
  if (issues.length > 0) {
    errorText.value = t(issueMessageKey(issues[0]));
    return;
  }

  submitting.value = true;
  errorText.value = '';
  const result = await confirmReset(token, password.value);
  submitting.value = false;

  if (result.ok) {
    toasts.add('success', t('auth.reset.success'));
    await router.replace('/login');
  } else {
    errorText.value = t(result.messageKey);
  }
}
</script>

<template>
  <AuthCard v-if="!token" :title="t('auth.reset.title')">
    <p class="auth-error">{{ t('auth.reset.invalidLink.heading') }}</p>
    <RouterLink class="auth-link" to="/forgot-password">{{ t('auth.reset.invalidLink.cta') }}</RouterLink>
  </AuthCard>

  <AuthCard v-else :title="t('auth.reset.title')">
    <form class="auth-form" @submit.prevent="onSubmit">
      <ul class="auth-rules">
        <li v-for="key in PASSWORD_RULE_KEYS" :key="key">
          {{ t(key, { min: PASSWORD_MIN_LENGTH, max: PASSWORD_MAX_LENGTH }) }}
        </li>
      </ul>
      <BaseInput
        v-model="password"
        :label="t('auth.reset.password.label')"
        type="password"
        autocomplete="new-password"
        name="new-password"
        required
      />
      <BaseInput
        v-model="confirm"
        :label="t('auth.reset.confirm.label')"
        type="password"
        autocomplete="new-password"
        name="confirm-password"
        required
      />
      <p v-if="errorText" class="auth-error" role="alert">{{ errorText }}</p>
      <BaseButton type="submit" size="lg" :disabled="submitting" :loading="submitting">
        {{ t('auth.reset.submit') }}
      </BaseButton>
    </form>
  </AuthCard>
</template>
