<script setup lang="ts">
import { ref, computed, nextTick } from 'vue';
import { Send, Paperclip } from 'lucide-vue-next';
import IconButton from './IconButton.vue';

const emit = defineEmits<{
  send: [message: string];
}>();

const props = defineProps<{
  disabled?: boolean;
}>();

const text = ref('');
const textareaRef = ref<HTMLTextAreaElement | null>(null);

const canSend = computed(() => text.value.trim().length > 0 && !props.disabled);

function handleSend() {
  if (!canSend.value) return;
  emit('send', text.value.trim());
  text.value = '';
  nextTick(autoGrow);
}

function handleKeydown(e: KeyboardEvent) {
  // Desktop: Enter sends, Shift+Enter newline
  if (e.key === 'Enter' && !e.shiftKey && window.innerWidth >= 768) {
    e.preventDefault();
    handleSend();
  }
}

function autoGrow() {
  const el = textareaRef.value;
  if (!el) return;
  el.style.height = 'auto';
  const maxH = 6 * 22; // ~6 lines
  el.style.height = Math.min(el.scrollHeight, maxH) + 'px';
}
</script>

<template>
  <div class="input-bar">
    <IconButton aria-label="Attach file" :disabled="true" class="attach-btn">
      <Paperclip :size="20" :stroke-width="1.75" />
    </IconButton>
    <textarea
      ref="textareaRef"
      v-model="text"
      class="input-textarea"
      placeholder="Ask admino anything&hellip;"
      rows="1"
      :disabled="disabled"
      @input="autoGrow"
      @keydown="handleKeydown"
    />
    <button
      class="send-btn"
      :disabled="!canSend"
      aria-label="Send"
      @click="handleSend"
    >
      <Send :size="20" :stroke-width="1.75" />
      <span class="send-label">Send</span>
    </button>
  </div>
</template>

<style scoped>
.input-bar {
  display: flex;
  align-items: flex-end;
  gap: var(--space-2);
  padding: var(--space-3) var(--space-4);
  background: var(--color-bg-surface);
  border-top: 1px solid var(--color-border);
  padding-bottom: calc(var(--space-3) + env(safe-area-inset-bottom, 0px));
}

.attach-btn {
  flex-shrink: 0;
}

.input-textarea {
  flex: 1;
  resize: none;
  padding: var(--space-2) var(--space-3);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-input);
  background: #FFFFFF;
  font-family: var(--font-body);
  font-size: var(--fs-body);
  line-height: 22px;
  color: var(--color-text);
  min-height: 44px;
  max-height: 132px;
  overflow-y: auto;
}

.input-textarea::placeholder {
  color: #8A9199;
}

.input-textarea:focus {
  outline: 2px solid rgba(7, 94, 84, 0.18);
  outline-offset: 0;
  border-color: var(--color-primary);
}

.send-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  min-height: 44px;
  min-width: 44px;
  padding: 0 var(--space-3);
  background: var(--color-primary);
  color: var(--color-text-on-dark);
  border-radius: var(--radius-input);
  font-weight: var(--fw-semibold);
  font-size: var(--fs-body);
  cursor: pointer;
  transition: var(--transition-hover);
  flex-shrink: 0;
}

.send-btn:hover:not(:disabled) {
  background: var(--color-primary-hover);
}

.send-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.send-label {
  display: none;
}

@media (min-width: 768px) {
  .send-label {
    display: inline;
  }
}
</style>
