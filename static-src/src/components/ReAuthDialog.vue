<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { ShieldAlert } from 'lucide-vue-next';
import BaseButton from './BaseButton.vue';
import I18nT from './I18nT.vue';
import { useI18n, type MessageKey } from '@/i18n';

const { t } = useI18n();

const props = defineProps<{
  tool: string;
  action: string;
  label: string;
}>();

const emit = defineEmits<{
  confirm: [token: string];
  cancel: [];
}>();

const token = ref('');
const inputRef = ref<HTMLInputElement | null>(null);

onMounted(() => {
  inputRef.value?.focus();
});

const TOOL_LABEL_KEYS: Record<string, MessageKey> = {
  gmail: 'tools.gmail.label',
  outlook: 'tools.outlook.label',
  google_calendar: 'tools.googleCalendar.label',
  outlook_calendar: 'tools.outlookCalendar.label',
};

const toolLabel = computed(() =>
  Object.hasOwn(TOOL_LABEL_KEYS, props.tool) ? t(TOOL_LABEL_KEYS[props.tool]) : props.tool,
);

function submit() {
  if (token.value) {
    const value = token.value;
    token.value = '';
    emit('confirm', value);
  }
}
</script>

<template>
  <Teleport to="body">
    <div class="reauth-backdrop" @click.self="$emit('cancel')">
      <div class="reauth-dialog" role="dialog" aria-modal="true" @click.stop>
        <div class="reauth-icon">
          <ShieldAlert :size="20" :stroke-width="1.75" />
        </div>
        <div>
          <div class="reauth-title">{{ t('reauth.title') }}</div>
          <I18nT tag="div" class="reauth-sub" keypath="reauth.body">
            <template #action><b>{{ action }}</b></template>
            <template #tool><b>{{ toolLabel }}</b></template>
          </I18nT>
        </div>
        <div class="reauth-field">
          <label class="reauth-field-label">{{ t('reauth.tokenLabel') }}</label>
          <input
            ref="inputRef"
            v-model="token"
            type="password"
            class="reauth-input"
            :placeholder="t('reauth.tokenPlaceholder')"
            @keydown.enter="submit"
          />
          <div class="reauth-field-hint">{{ t('reauth.tokenHint') }}</div>
        </div>
        <div class="reauth-actions">
          <BaseButton variant="secondary" @click="$emit('cancel')">{{ t('common.cancel') }}</BaseButton>
          <BaseButton variant="warn" :disabled="!token" @click="submit">
            {{ t('reauth.submit') }}
          </BaseButton>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.reauth-backdrop {
  position: fixed;
  inset: 0;
  background: var(--color-overlay);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 500;
  animation: reauth-fade var(--dur-med) var(--ease);
}

.reauth-dialog {
  width: 90%;
  max-width: 420px;
  background: var(--color-bg-elevated);
  border-radius: var(--radius-card);
  padding: var(--space-6);
  box-shadow: var(--shadow-modal);
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  animation: reauth-scale var(--dur-med) var(--ease);
}

.reauth-icon {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  background: var(--color-warn-soft);
  border: 1px solid #F1D495;
  color: #B58127;
  display: grid;
  place-items: center;
}

.reauth-title {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 16px;
  color: var(--color-text);
}

.reauth-sub {
  font-size: 13px;
  color: var(--color-text-muted);
  margin-top: 4px;
  line-height: 1.5;
}

.reauth-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.reauth-field-label {
  font-size: 13px;
  font-weight: 500;
  color: #475560;
}

.reauth-input {
  padding: 10px 14px;
  background: #FFFFFF;
  border: 1px solid #CFC7B4;
  border-radius: var(--radius-input);
  font-size: 14px;
  font-weight: 400;
  color: var(--color-text);
  transition: border-color var(--dur-fast) var(--ease);
}

.reauth-input::placeholder {
  color: #8A9199;
  font-weight: 400;
}

.reauth-input:focus {
  outline: 2px solid rgba(233, 162, 59, 0.22);
  outline-offset: 0;
  border-color: var(--color-warn);
}

.reauth-field-hint {
  font-size: 11.5px;
  color: var(--color-text-muted);
}

.reauth-actions {
  display: flex;
  gap: var(--space-3);
  justify-content: flex-end;
}

@keyframes reauth-fade {
  from { opacity: 0; }
  to { opacity: 1; }
}

@keyframes reauth-scale {
  from { transform: scale(0.95); opacity: 0; }
  to { transform: scale(1); opacity: 1; }
}
</style>
