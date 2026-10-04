<script setup lang="ts">
/**
 * Create-organization and edit-limits sheet of the Platform console
 * (issue #168). One form, two modes: `create` also collects the name and the
 * first Org Admin's email. Validation, unit conversion and the API call live
 * in `stores/platformOrgs.ts` / `services/platformOrgs.ts`; this component
 * only collects the input and forwards `submit`.
 */
import { ref, watch } from 'vue';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import { CREATE_DEFAULTS, type OrgCreateInput, type OrgFormField, type OrgLimitsInput } from '@/services/platformOrgs';
import { useI18n } from '@/i18n';

const { t } = useI18n();

const props = defineProps<{
  mode: 'create' | 'limits';
  /** Prefill for `limits` mode (`limitsInputFrom(org)`). */
  initial: OrgLimitsInput | null;
  busy: boolean;
  errors: Partial<Record<OrgFormField, string>>;
  error: string | null;
}>();

const emit = defineEmits<{
  submit: [input: OrgCreateInput];
  close: [];
}>();

const name = ref('');
const email = ref('');
const seats = ref('');
const budget = ref('');
const storage = ref('');

function reset(): void {
  const base = props.initial ?? { ...CREATE_DEFAULTS };
  name.value = '';
  email.value = '';
  seats.value = String(base.seats);
  budget.value = base.budgetChf;
  storage.value = String(base.storageGib);
}

watch(() => [props.mode, props.initial], reset, { immediate: true });

function onSubmit(): void {
  // Blank or non-numeric text becomes NaN, which the service rejects.
  emit('submit', {
    name: name.value,
    email: email.value,
    seats: seats.value.trim() === '' ? Number.NaN : Number(seats.value),
    budgetChf: budget.value,
    storageGib: storage.value.trim() === '' ? Number.NaN : Number(storage.value),
  });
}
</script>

<template>
  <Teleport to="body">
    <div class="sheet-backdrop" @click.self="!busy && $emit('close')">
      <form class="sheet" novalidate @submit.prevent="onSubmit">
        <div class="sheet-handle" />
        <h3 class="sheet-heading">
          {{ mode === 'create' ? t('platform.orgs.form.create.heading') : t('platform.orgs.form.limits.heading') }}
        </h3>

        <template v-if="mode === 'create'">
          <BaseInput
            v-model="name"
            :label="t('platform.orgs.form.name')"
            :error="errors.name"
            :disabled="busy"
            :maxlength="120"
            required
          />
          <BaseInput
            v-model="email"
            type="email"
            :label="t('platform.orgs.form.email')"
            :error="errors.email"
            autocomplete="off"
            :disabled="busy"
            required
          />
        </template>
        <BaseInput
          v-model="seats"
          type="number"
          :label="t('platform.orgs.form.seats')"
          :error="errors.seats"
          :disabled="busy"
        />
        <BaseInput
          v-model="budget"
          type="text"
          :label="t('platform.orgs.form.budget')"
          :error="errors.budgetChf"
          :disabled="busy"
        />
        <BaseInput
          v-model="storage"
          type="number"
          :label="t('platform.orgs.form.storage')"
          :error="errors.storageGib"
          :disabled="busy"
        />

        <p v-if="error" class="error-text" role="alert">{{ error }}</p>

        <div class="sheet-actions">
          <BaseButton type="button" variant="secondary" :disabled="busy" @click="$emit('close')">
            {{ t('common.cancel') }}
          </BaseButton>
          <BaseButton type="submit" variant="primary" :loading="busy">
            {{ mode === 'create' ? t('platform.orgs.form.create.submit') : t('platform.orgs.form.limits.submit') }}
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
  max-height: 90vh;
  overflow-y: auto;
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
