<script setup lang="ts">
import { ref } from 'vue';
import BaseInput from '@/components/BaseInput.vue';
import BaseToggle from '@/components/BaseToggle.vue';
import BaseButton from '@/components/BaseButton.vue';
import ConfirmSheet from '@/components/ConfirmSheet.vue';
import { useSettingsStore, type LLMProvider } from '@/stores/settings';
import { useChatStore } from '@/stores/chat';
import { useToastStore } from '@/stores/toasts';

const settings = useSettingsStore();
const chatStore = useChatStore();
const toasts = useToastStore();

const providers: { value: LLMProvider; label: string }[] = [
  { value: 'ollama', label: 'Ollama' },
  { value: 'claude', label: 'Claude' },
  { value: 'openai', label: 'OpenAI' },
];

const toolApprovalAlerts = ref(true);
const taskCompletedAlerts = ref(false);
const showClearConfirm = ref(false);

function onSettingSaved() {
  toasts.add('success', 'Saved');
}

function handleClearChat() {
  chatStore.clearThread();
  showClearConfirm.value = false;
  toasts.add('success', 'Chat cleared');
}

function handleNewSession() {
  settings.newSession();
  chatStore.clearThread();
  toasts.add('success', 'New session started');
}
</script>

<template>
  <div class="settings-page">
    <header class="page-header">
      <h1>Settings</h1>
    </header>

    <div class="page-content">
      <div class="settings-section">
        <h3>Agent</h3>
        <div class="setting-card">
          <div class="setting-row">
            <span class="setting-label">LLM Provider</span>
            <div class="segmented-control">
              <button
                v-for="p in providers"
                :key="p.value"
                class="segment"
                :class="{ active: settings.provider === p.value }"
                @click="settings.provider = p.value; onSettingSaved()"
              >
                {{ p.label }}
              </button>
            </div>
          </div>

          <BaseInput
            v-model="settings.model"
            label="Model"
            placeholder="e.g. llama3.2:3b"
            @blur="onSettingSaved"
          />

          <BaseInput
            v-if="settings.provider === 'ollama'"
            v-model="settings.ollamaUrl"
            label="Ollama URL"
            placeholder="http://localhost:11434"
            @blur="onSettingSaved"
          />

          <div class="setting-row">
            <span class="setting-label">Session</span>
            <BaseButton variant="secondary" @click="handleNewSession">
              New Session
            </BaseButton>
          </div>
        </div>
      </div>

      <div class="settings-section">
        <h3>Appearance</h3>
        <div class="setting-card">
          <div class="setting-row">
            <div>
              <span class="setting-label">Theme</span>
              <span class="caption">Dark mode coming soon.</span>
            </div>
            <div class="segmented-control">
              <button class="segment active" disabled>Light</button>
              <button class="segment" disabled>Dark</button>
              <button class="segment" disabled>System</button>
            </div>
          </div>
        </div>
      </div>

      <div class="settings-section">
        <h3>Notifications</h3>
        <div class="setting-card">
          <div class="setting-row">
            <span class="setting-label">Tool approval alerts</span>
            <BaseToggle v-model="toolApprovalAlerts" />
          </div>
          <div class="setting-row">
            <span class="setting-label">Task completed alerts</span>
            <BaseToggle v-model="taskCompletedAlerts" />
          </div>
        </div>
      </div>

      <div class="settings-section">
        <h3>Data</h3>
        <div class="setting-card">
          <div class="setting-row">
            <span class="setting-label">Clear conversation</span>
            <BaseButton variant="destructive" @click="showClearConfirm = true">
              Clear
            </BaseButton>
          </div>
        </div>
      </div>

      <div class="settings-section">
        <h3>About</h3>
        <div class="setting-card">
          <div class="about-line caption">
            <strong>admino</strong> v1.0.0
          </div>
          <div class="about-line caption trust-badge">
            Running locally. Your data never leaves this machine.
          </div>
        </div>
      </div>
    </div>

    <ConfirmSheet
      v-if="showClearConfirm"
      heading="Clear conversation?"
      subtext="This will remove all messages and tool call history from the current session."
      confirm-label="Clear"
      variant="destructive"
      @confirm="handleClearChat"
      @cancel="showClearConfirm = false"
    />
  </div>
</template>

<style scoped>
.settings-page {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}

.page-header {
  padding: var(--space-4);
  border-bottom: 1px solid var(--color-border);
  background: var(--color-bg-surface);
  flex-shrink: 0;
}

.page-content {
  flex: 1;
  overflow-y: auto;
  padding: var(--space-4);
  max-width: var(--content-max);
  margin: 0 auto;
  width: 100%;
}

.settings-section {
  margin-bottom: var(--space-6);
}

.settings-section h3 {
  margin-bottom: var(--space-3);
}

.setting-card {
  background: var(--color-bg-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  padding: var(--space-4);
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.setting-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
}

.setting-label {
  font-weight: var(--fw-semibold);
  font-size: var(--fs-body);
}

.segmented-control {
  display: flex;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-input);
  overflow: hidden;
}

.segment {
  padding: var(--space-2) var(--space-4);
  font-size: var(--fs-caption);
  font-weight: var(--fw-medium);
  cursor: pointer;
  transition: var(--transition-hover);
  color: var(--color-text-muted);
  border-right: 1px solid var(--color-border);
  min-height: 36px;
}

.segment:last-child {
  border-right: none;
}

.segment.active {
  background: var(--color-primary);
  color: var(--color-text-on-dark);
}

.segment:hover:not(.active):not(:disabled) {
  background: var(--color-bg);
}

.segment:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.about-line {
  padding: var(--space-1) 0;
}

.trust-badge {
  color: var(--color-sage);
  font-weight: var(--fw-medium);
}
</style>
