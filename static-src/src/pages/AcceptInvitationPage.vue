<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import AuthCard from '@/components/AuthCard.vue';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import { INVITATION_ROLE_LABEL_KEYS, homePath } from '@/services/access';
import { acceptInvite, loadInvitation } from '@/services/authFlows';
import { consumeLinkToken } from '@/services/linkToken';
import {
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  PASSWORD_RULE_KEYS,
  checkNewPassword,
  issueMessageKey,
} from '@/services/passwordPolicy';
import { useAuthStore } from '@/stores/auth';
import { t } from '@/i18n';
import type { InvitationDetails } from '@/api/types';

const router = useRouter();
const auth = useAuthStore();

// Read once, on setup: strips the token from the address bar and history
// immediately (window.history.state is preserved for vue-router).
const token = consumeLinkToken(window.location, {
  replaceState: (_data, _unused, url) => window.history.replaceState(window.history.state, '', url),
});

const loading = ref(true);
const invitation = ref<InvitationDetails | null>(null);
const loadErrorText = ref('');

const name = ref('');
const password = ref('');
const confirm = ref('');
const submitting = ref(false);
const submitErrorText = ref('');

onMounted(async () => {
  if (!token) {
    loading.value = false;
    return;
  }
  const result = await loadInvitation(token);
  loading.value = false;
  if (result.ok) {
    invitation.value = result.invitation;
  } else {
    loadErrorText.value = t(result.messageKey);
  }
});

async function onSubmit(): Promise<void> {
  if (submitting.value || !token || !invitation.value) return;

  const issues = checkNewPassword(password.value, confirm.value, invitation.value.email);
  if (issues.length > 0) {
    submitErrorText.value = t(issueMessageKey(issues[0]));
    return;
  }

  submitting.value = true;
  submitErrorText.value = '';
  const result = await acceptInvite(token, name.value, password.value);

  if (!result.ok) {
    submitting.value = false;
    submitErrorText.value = t(result.messageKey);
    return;
  }

  await auth.loadMe();
  submitting.value = false;
  await router.replace(homePath(auth.role));
}
</script>

<template>
  <AuthCard v-if="!token" :title="t('auth.invitation.title')">
    <p class="auth-error">{{ t('auth.invitation.invalidLink.heading') }}</p>
    <RouterLink class="auth-link" to="/login">{{ t('auth.login.title') }}</RouterLink>
  </AuthCard>

  <AuthCard v-else-if="loading" :title="t('auth.invitation.title')">
    <p class="auth-subtitle">{{ t('common.loading') }}</p>
  </AuthCard>

  <AuthCard v-else-if="!invitation" :title="t('auth.invitation.title')">
    <p class="auth-error">{{ loadErrorText }}</p>
    <RouterLink class="auth-link" to="/login">{{ t('auth.login.title') }}</RouterLink>
  </AuthCard>

  <AuthCard v-else :title="t('auth.invitation.title')">
    <form class="auth-form" @submit.prevent="onSubmit">
      <div class="auth-form-row">
        <span class="auth-form-label">{{ t('auth.invitation.org.label') }}</span>
        <span class="auth-readonly">{{ invitation.org_name }}</span>
      </div>
      <div class="auth-form-row">
        <span class="auth-form-label">{{ t('auth.invitation.role.label') }}</span>
        <span class="auth-readonly">{{ t(INVITATION_ROLE_LABEL_KEYS[invitation.role]) }}</span>
      </div>
      <BaseInput
        :model-value="invitation.email"
        :label="t('auth.invitation.email.label')"
        type="email"
        autocomplete="username"
        name="email"
        readonly
      />
      <BaseInput
        v-model="name"
        :label="t('auth.invitation.name.label')"
        autocomplete="name"
        name="name"
        :maxlength="120"
        required
      />
      <ul class="auth-rules">
        <li v-for="key in PASSWORD_RULE_KEYS" :key="key">
          {{ t(key, { min: PASSWORD_MIN_LENGTH, max: PASSWORD_MAX_LENGTH }) }}
        </li>
      </ul>
      <BaseInput
        v-model="password"
        :label="t('auth.invitation.password.label')"
        type="password"
        autocomplete="new-password"
        name="new-password"
        required
      />
      <BaseInput
        v-model="confirm"
        :label="t('auth.invitation.confirm.label')"
        type="password"
        autocomplete="new-password"
        name="confirm-password"
        required
      />
      <p v-if="submitErrorText" class="auth-error" role="alert">{{ submitErrorText }}</p>
      <BaseButton type="submit" size="lg" :disabled="submitting" :loading="submitting">
        {{ t('auth.invitation.submit') }}
      </BaseButton>
    </form>
  </AuthCard>
</template>

<style scoped>
.auth-form-row {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.auth-form-label {
  font-size: 13px;
  font-weight: 500;
  color: #475560;
}
</style>
