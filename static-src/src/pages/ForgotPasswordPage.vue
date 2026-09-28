<script setup lang="ts">
import { ref } from 'vue';
import AuthCard from '@/components/AuthCard.vue';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import { requestReset } from '@/services/authFlows';
import { t } from '@/i18n';

const email = ref('');
const submitting = ref(false);
const success = ref(false);
const errorText = ref('');

async function onSubmit(): Promise<void> {
  if (submitting.value) return;
  submitting.value = true;
  errorText.value = '';
  const result = await requestReset(email.value);
  submitting.value = false;

  if (result.ok) {
    success.value = true;
  } else {
    errorText.value = t(result.messageKey);
  }
}
</script>

<template>
  <AuthCard :title="t('auth.forgotPassword.title')">
    <p v-if="success" class="auth-success">{{ t('auth.forgotPassword.success') }}</p>
    <form v-else class="auth-form" @submit.prevent="onSubmit">
      <p class="auth-subtitle">{{ t('auth.forgotPassword.subtitle') }}</p>
      <BaseInput
        v-model="email"
        :label="t('auth.forgotPassword.email.label')"
        type="email"
        autocomplete="username"
        name="email"
        required
      />
      <p v-if="errorText" class="auth-error" role="alert">{{ errorText }}</p>
      <BaseButton type="submit" size="lg" :disabled="submitting" :loading="submitting">
        {{ t('auth.forgotPassword.submit') }}
      </BaseButton>
    </form>
    <RouterLink class="auth-link" to="/login">{{ t('auth.forgotPassword.backToLogin') }}</RouterLink>
  </AuthCard>
</template>
