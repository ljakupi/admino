<script setup lang="ts">
/**
 * Defaults tab of the Platform console (issue #168): a form over the
 * platform settings draft (Model, Limits, Files, Retention, Security) with
 * per-field errors, Save/Reset and the residency confirmation dialog.
 * Validation, the patch and the residency rule live in
 * `stores/platformDefaults.ts` / `services/platformDefaults.ts`; this
 * component only binds the draft and forwards events. Secrets are never
 * shown: only whether a provider's key or token is configured.
 */
import { computed, onMounted } from 'vue';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import BaseToggle from '@/components/BaseToggle.vue';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import { usePlatformDefaultsStore } from '@/stores/platformDefaults';
import {
  DEFAULTS_BOUNDS,
  LLM_PROVIDERS,
  MODEL_FIELD,
  isLlmProvider,
  modelOptions,
  providerKeyConfigured,
} from '@/services/platformDefaults';
import { useI18n, type MessageKey } from '@/i18n';

const { t, formatNumber } = useI18n();
const store = usePlatformDefaultsStore();

onMounted(() => {
  void store.load();
});

const NUMERIC_SECTIONS = ['limits', 'files', 'retention', 'security'] as const;
type NumericSection = (typeof NUMERIC_SECTIONS)[number];

function fieldsOf(section: string): string[] {
  return Object.keys(DEFAULTS_BOUNDS)
    .filter((path) => path.startsWith(`${section}.`))
    .map((path) => path.slice(section.length + 1));
}

function labelOf(path: string): string {
  return t(`platform.defaults.field.${path}` as MessageKey);
}

function hintOf(path: string): string {
  const bounds = DEFAULTS_BOUNDS[path];
  return t('platform.defaults.range', { min: formatNumber(bounds.min), max: formatNumber(bounds.max) });
}

// The draft's numeric sections are addressed by "<section>.<field>" paths
// that come from DEFAULTS_BOUNDS, so a cast is needed to index them.
type NumberSections = Record<string, Record<string, number>>;

function numberValue(section: string, field: string): number | string {
  const draft = store.draft as unknown as NumberSections | null;
  const value = draft?.[section]?.[field];
  return value === undefined || Number.isNaN(value) ? '' : value;
}

function setNumber(section: string, field: string, raw: string): void {
  const draft = store.draft as unknown as NumberSections | null;
  if (!draft) return;
  // A blank field becomes NaN so validation rejects it instead of saving 0.
  draft[section][field] = raw.trim() === '' ? Number.NaN : Number(raw);
}

const provider = computed(() => (store.draft && isLlmProvider(store.draft.llm.provider) ? store.draft.llm.provider : null));
const modelField = computed(() => (provider.value ? MODEL_FIELD[provider.value] : null));
const options = computed(() => {
  if (!store.settings || !provider.value) return [];
  return modelOptions(store.settings.llm, provider.value);
});
const modelValue = computed<string>({
  get: () => (store.draft && modelField.value ? store.draft.llm[modelField.value] : ''),
  set: (value) => {
    if (store.draft && modelField.value) store.draft.llm[modelField.value] = value;
  },
});
const modelChoices = computed(() => (options.value.includes(modelValue.value) || !modelValue.value ? options.value : [modelValue.value, ...options.value]));
const keyMissing = computed(() =>
  store.settings && provider.value ? providerKeyConfigured(store.settings.llm, provider.value) === false : false,
);

function onProviderChange(event: Event): void {
  if (store.draft) store.draft.llm.provider = (event.target as HTMLSelectElement).value as typeof store.draft.llm.provider;
}
</script>

<template>
  <div class="defaults-panel">
    <p v-if="store.loadError" class="error-text" role="alert">
      {{ store.loadError }}
      <button type="button" class="link-btn" @click="store.load()">{{ t('common.retry') }}</button>
    </p>
    <p v-if="store.loading && !store.loaded" class="caption" role="status">{{ t('platform.defaults.loadingLabel') }}</p>

    <form v-if="store.draft && store.settings" class="defaults-form" novalidate @submit.prevent="store.save()">
      <section class="card">
        <h3>{{ t('platform.defaults.section.model') }}</h3>

        <div class="field">
          <label class="field-label" for="pd-provider">{{ t('platform.defaults.provider') }}</label>
          <select id="pd-provider" class="select" :value="store.draft.llm.provider" :disabled="store.saving" @change="onProviderChange">
            <option v-for="p in LLM_PROVIDERS" :key="p" :value="p">{{ t(`platform.defaults.provider.${p}` as MessageKey) }}</option>
          </select>
          <span v-if="store.fieldErrors['llm.provider']" class="field-error caption">{{ store.fieldErrors['llm.provider'] }}</span>
          <span v-if="keyMissing" class="field-warn caption">{{ t('platform.defaults.keyMissing') }}</span>
        </div>

        <div v-if="modelField" class="field">
          <label class="field-label" for="pd-model">{{ t('platform.defaults.model') }}</label>
          <select v-if="options.length > 0" id="pd-model" v-model="modelValue" class="select" :disabled="store.saving">
            <option v-for="m in modelChoices" :key="m" :value="m">{{ m }}</option>
          </select>
          <BaseInput
            v-else
            v-model="modelValue"
            :disabled="store.saving"
            :error="store.fieldErrors[`llm.${modelField}`]"
          />
          <span v-if="options.length > 0 && store.fieldErrors[`llm.${modelField}`]" class="field-error caption">
            {{ store.fieldErrors[`llm.${modelField}`] }}
          </span>
        </div>

        <div v-for="field in fieldsOf('llm')" :key="field" class="field">
          <label class="field-label" :for="`pd-llm-${field}`">{{ labelOf(`llm.${field}`) }}</label>
          <input
            :id="`pd-llm-${field}`"
            class="num"
            type="number"
            inputmode="numeric"
            :value="numberValue('llm', field)"
            :disabled="store.saving"
            @input="setNumber('llm', field, ($event.target as HTMLInputElement).value)"
          />
          <span v-if="store.fieldErrors[`llm.${field}`]" class="field-error caption">{{ store.fieldErrors[`llm.${field}`] }}</span>
          <span v-else class="field-hint caption">{{ hintOf(`llm.${field}`) }}</span>
        </div>

        <div class="field toggle-field">
          <span class="field-label">{{ t('platform.defaults.imageInput') }}</span>
          <BaseToggle
            v-model="store.draft.llm.image_input"
            :aria-label="t('platform.defaults.imageInput')"
            :disabled="store.saving"
          />
          <span v-if="store.fieldErrors['llm.image_input']" class="field-error caption">{{ store.fieldErrors['llm.image_input'] }}</span>
        </div>

        <p class="caption">{{ t('platform.defaults.residencyOrgs', { count: formatNumber(store.settings.llm.residency_orgs) }) }}</p>
      </section>

      <section v-for="section in NUMERIC_SECTIONS" :key="section" class="card">
        <h3>{{ t(`platform.defaults.section.${section as NumericSection}` as MessageKey) }}</h3>
        <div v-for="field in fieldsOf(section)" :key="field" class="field">
          <label class="field-label" :for="`pd-${section}-${field}`">{{ labelOf(`${section}.${field}`) }}</label>
          <input
            :id="`pd-${section}-${field}`"
            class="num"
            type="number"
            inputmode="numeric"
            :value="numberValue(section, field)"
            :disabled="store.saving"
            @input="setNumber(section, field, ($event.target as HTMLInputElement).value)"
          />
          <span v-if="store.fieldErrors[`${section}.${field}`]" class="field-error caption">
            {{ store.fieldErrors[`${section}.${field}`] }}
          </span>
          <span v-else class="field-hint caption">{{ hintOf(`${section}.${field}`) }}</span>
        </div>
      </section>

      <p v-if="store.saveError" class="error-text" role="alert">{{ store.saveError }}</p>

      <div class="form-actions">
        <BaseButton type="button" variant="secondary" :disabled="!store.dirty || store.saving" @click="store.reset()">
          {{ t('platform.defaults.reset') }}
        </BaseButton>
        <BaseButton type="submit" variant="primary" :disabled="!store.dirty" :loading="store.saving">
          {{ t('platform.defaults.save') }}
        </BaseButton>
      </div>
    </form>

    <ConfirmSheet
      v-if="store.residencyConfirm && store.residencyConfirmText"
      :heading="store.residencyConfirmText.title"
      :subtext="store.residencyConfirmText.body"
      :confirm-label="store.residencyConfirmText.confirm"
      variant="destructive"
      :busy="store.saving"
      @confirm="store.confirmResidency()"
      @cancel="store.cancelResidency()"
    />
  </div>
</template>

<style scoped>
.defaults-panel {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.defaults-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.card {
  padding: var(--space-4);
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.toggle-field {
  flex-direction: row;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
}

.field-label {
  font-size: 13px;
  font-weight: 500;
  color: #475560;
}

.select,
.num {
  min-height: 44px;
  padding: 10px 14px;
  border-radius: var(--radius-input);
  border: 1px solid var(--color-border-strong);
  background: var(--color-bg-elevated);
  color: var(--color-text);
  font-size: 14px;
}

.field-hint {
  color: var(--color-text-muted);
}

.field-error,
.error-text {
  color: var(--color-error);
}

.field-warn {
  color: #8A5A14;
}

.error-text {
  font-size: 13px;
  margin: 0;
}

.link-btn {
  min-height: 44px;
  padding: 0 8px;
  background: transparent;
  border: 0;
  color: var(--color-primary);
  font: inherit;
  text-decoration: underline;
  cursor: pointer;
}

.form-actions {
  display: flex;
  gap: var(--space-3);
  justify-content: flex-end;
}
</style>
