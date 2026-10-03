<script setup lang="ts">
/**
 * Edit (name/email) sheet (issue #165): prefilled from `user`, with the
 * email-change hint and the store's `editError` shown inline. Validation and
 * the diff/API call live in `stores/orgUsers.ts`; this component only
 * collects the input and forwards `submit`.
 */
import { ref, watch } from 'vue';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import { useI18n } from '@/i18n';
import type { OrgUser } from '@/api/types';

const { t } = useI18n();

const props = defineProps<{
  user: OrgUser | null;
  busy: boolean;
  error: string | null;
}>();

const emit = defineEmits<{
  submit: [input: { name: string; email: string }];
  close: [];
}>();

const name = ref('');
const email = ref('');

watch(
  () => props.user,
  (user) => {
    if (user !== null) {
      name.value = user.name ?? '';
      email.value = user.email;
    }
  },
  { immediate: true },
);

function onSubmit(): void {
  emit('submit', { name: name.value, email: email.value });
}
</script>

<template>
  <Teleport to="body">
    <div v-if="user !== null" class="sheet-backdrop" @click.self="$emit('close')">
      <form class="sheet" @submit.prevent="onSubmit">
        <div class="sheet-handle" />
        <h3 class="sheet-heading">{{ t('orgUsers.edit.heading') }}</h3>

        <BaseInput v-model="name" :label="t('orgUsers.edit.name.label')" :disabled="busy" />
        <BaseInput
          v-model="email"
          type="email"
          :label="t('orgUsers.edit.email.label')"
          :hint="t('orgUsers.edit.emailHint')"
          :disabled="busy"
          required
        />

        <p v-if="error" class="error-text" role="alert">{{ error }}</p>

        <div class="sheet-actions">
          <BaseButton type="button" variant="secondary" :disabled="busy" @click="$emit('close')">
            {{ t('common.cancel') }}
          </BaseButton>
          <BaseButton type="submit" variant="primary" :loading="busy">
            {{ t('orgUsers.edit.submit') }}
          </BaseButton>
        </div>
      </form>
    </div>
  </Teleport>
</template>

<style scoped>
.sheet-backdrop {
  position: fixed;
  inset: 0;
  background: var(--color-overlay);
  display: flex;
  align-items: flex-end;
  justify-content: center;
  z-index: 500;
}

@media (min-width: 768px) {
  .sheet-backdrop {
    align-items: center;
  }
}

.sheet {
  background: var(--color-bg-elevated);
  padding: var(--space-6);
  width: 90%;
  max-width: 420px;
  border-radius: var(--radius-pill) var(--radius-pill) 0 0;
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

@media (min-width: 768px) {
  .sheet {
    border-radius: var(--radius-card);
    box-shadow: var(--shadow-modal);
  }
}

.sheet-handle {
  width: 36px;
  height: 4px;
  background: var(--color-border-strong);
  border-radius: 2px;
  margin: 0 auto;
}

@media (min-width: 768px) {
  .sheet-handle {
    display: none;
  }
}

.sheet-heading {
  margin: 0;
}

.error-text {
  color: var(--color-error);
  font-size: 13px;
  margin: 0;
}

.sheet-actions {
  display: flex;
  gap: var(--space-3);
  justify-content: flex-end;
}
</style>
