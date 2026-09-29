<script setup lang="ts">
import { ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import AuthCard from '@/components/AuthCard.vue';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import { safeRedirect } from '@/router/guards';
import { homePath } from '@/services/access';
import { loginMessageKey } from '@/services/authFlows';
import { useAuthStore } from '@/stores/auth';
import { t } from '@/i18n';

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();

const email = ref('');
const password = ref('');
const submitting = ref(false);
const errorText = ref('');

async function onSubmit(): Promise<void> {
  if (submitting.value) return;
  submitting.value = true;
  errorText.value = '';
  const outcome = await auth.login(email.value, password.value);
  submitting.value = false;

  if (outcome === 'ok') {
    const redirect = safeRedirect(route.query.redirect);
    await router.replace(redirect ?? homePath(auth.role));
    return;
  }

  password.value = '';
  errorText.value = t(loginMessageKey(outcome));
}
</script>

<template>
  <AuthCard :title="t('auth.login.title')">
    <form class="auth-form" @submit.prevent="onSubmit">
      <BaseInput
        v-model="email"
        :label="t('auth.login.email.label')"
        type="email"
        autocomplete="username"
        name="email"
        required
      />
      <BaseInput
        v-model="password"
        :label="t('auth.login.password.label')"
        type="password"
        autocomplete="current-password"
        name="current-password"
        required
      />
      <p v-if="errorText" class="auth-error" role="alert">{{ errorText }}</p>
      <BaseButton type="submit" size="lg" :disabled="submitting" :loading="submitting">
        {{ t('auth.login.submit') }}
      </BaseButton>
    </form>
    <RouterLink class="auth-link" to="/forgot-password">{{ t('auth.login.forgotPassword') }}</RouterLink>
  </AuthCard>
</template>
