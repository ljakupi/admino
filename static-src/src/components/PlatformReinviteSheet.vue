<script setup lang="ts">
/**
 * Re-invite sheet of the Platform console (issue #168): an optional new
 * email. Blank resends to the same address, a new address replaces it. The
 * logic (validation, API call) is in `stores/platformOrgDetail.ts`.
 */
import { ref } from 'vue';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import { useI18n } from '@/i18n';

const { t } = useI18n();

defineProps<{
  busy: boolean;
  error: string | null;
}>();

const emit = defineEmits<{
  submit: [email: string];
  close: [];
}>();

const email = ref('');
</script>

<template>
  <Teleport to="body">
    <div class="sheet-backdrop" @click.self="!busy && $emit('close')">
      <form class="sheet" novalidate @submit.prevent="emit('submit', email)">
        <div class="sheet-handle" />
        <h3 class="sheet-heading">{{ t('platform.users.reinvite.heading') }}</h3>
        <BaseInput
          v-model="email"
          type="email"
          :label="t('platform.users.reinvite.email')"
          :hint="t('platform.users.reinvite.hint')"
          autocomplete="off"
          :disabled="busy"
        />
        <p v-if="error" class="error-text" role="alert">{{ error }}</p>
        <div class="sheet-actions">
          <BaseButton type="button" variant="secondary" :disabled="busy" @click="$emit('close')">
            {{ t('common.cancel') }}
          </BaseButton>
          <BaseButton type="submit" variant="primary" :loading="busy">
            {{ t('platform.users.reinvite.submit') }}
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
