<script setup lang="ts">
/**
 * Invite sheet (issue #165): email + role (`ASSIGNABLE_ROLES` only — Viewer
 * is never offered), the seat label and the store's `inviteError` shown
 * inline. All business logic (validation, the API call, seat bookkeeping)
 * lives in `stores/orgUsers.ts`; this component only collects the input and
 * forwards `submit`.
 */
import { ref, watch } from 'vue';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import { ASSIGNABLE_ROLES, ROLE_LABEL_KEYS } from '@/services/orgUsers';
import { useI18n } from '@/i18n';
import type { MemberRole } from '@/api/types';

const { t } = useI18n();

const props = defineProps<{
  open: boolean;
  busy: boolean;
  error: string | null;
  seatText: string | null;
  noFreeSeat: boolean;
}>();

const emit = defineEmits<{
  submit: [email: string, role: MemberRole];
  close: [];
}>();

const email = ref('');
const role = ref<MemberRole>('editor');

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      email.value = '';
      role.value = 'editor';
    }
  },
);

function onSubmit(): void {
  emit('submit', email.value, role.value);
}
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="sheet-backdrop" @click.self="$emit('close')">
      <form class="sheet" @submit.prevent="onSubmit">
        <div class="sheet-handle" />
        <h3 class="sheet-heading">{{ t('orgUsers.invite.heading') }}</h3>
        <p v-if="seatText" class="seat-note caption" :class="{ full: noFreeSeat }">{{ seatText }}</p>

        <BaseInput
          v-model="email"
          type="email"
          :label="t('orgUsers.invite.email.label')"
          autocomplete="email"
          :disabled="busy"
          required
        />

        <div class="field">
          <label class="field-label">{{ t('orgUsers.invite.role.label') }}</label>
          <select v-model="role" class="role-select" :disabled="busy">
            <option v-for="r in ASSIGNABLE_ROLES" :key="r" :value="r">{{ t(ROLE_LABEL_KEYS[r]) }}</option>
          </select>
        </div>

        <p v-if="error" class="error-text" role="alert">{{ error }}</p>

        <div class="sheet-actions">
          <BaseButton type="button" variant="secondary" :disabled="busy" @click="$emit('close')">
            {{ t('common.cancel') }}
          </BaseButton>
          <BaseButton type="submit" variant="primary" :loading="busy">
            {{ t('orgUsers.invite.submit') }}
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

.seat-note {
  color: var(--color-text-muted);
}

.seat-note.full {
  color: var(--color-error);
}

.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.field-label {
  font-size: 13px;
  font-weight: 500;
  color: #475560;
}

.role-select {
  min-height: 44px;
  padding: 10px 14px;
  border-radius: var(--radius-input);
  border: 1px solid var(--color-border-strong);
  background: var(--color-bg-elevated);
  color: var(--color-text);
  font-size: 14px;
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
