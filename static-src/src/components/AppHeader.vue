<script setup lang="ts">
import { Trash2, Download, MoreVertical } from 'lucide-vue-next';
import StatusDot from './StatusDot.vue';
import IconButton from './IconButton.vue';
import { useConnectionStore } from '@/stores/connection';
import { useChatStore } from '@/stores/chat';
import { t } from '@/i18n';
import { ref } from 'vue';

const connection = useConnectionStore();
const chatStore = useChatStore();
const showMobileMenu = ref(false);

function clearChat() {
  chatStore.clearThread();
  showMobileMenu.value = false;
}
</script>

<template>
  <header class="chat-header">
    <div class="header-left">
      <span class="wordmark">admino</span>
      <StatusDot :state="connection.state" />
    </div>
    <div class="header-actions desktop-only">
      <IconButton :aria-label="t('chat.header.clearChat')" @click="clearChat">
        <Trash2 :size="18" :stroke-width="1.75" />
      </IconButton>
    </div>
    <div class="header-actions mobile-only">
      <IconButton :aria-label="t('chat.header.menu')" @click="showMobileMenu = !showMobileMenu">
        <MoreVertical :size="18" :stroke-width="1.75" />
      </IconButton>
      <div v-if="showMobileMenu" class="dropdown" @click="showMobileMenu = false">
        <button class="dropdown-item" @click="clearChat">{{ t('chat.header.clearChat') }}</button>
      </div>
    </div>
  </header>
</template>

<style scoped>
.chat-header {
  height: var(--header-h);
  min-height: var(--header-h);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 var(--space-4);
  border-bottom: 1px solid var(--color-border);
  background: var(--color-bg-surface);
  position: sticky;
  top: 0;
  z-index: 10;
}

.header-left {
  display: flex;
  align-items: center;
  gap: var(--space-3);
}

.wordmark {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 20px;
  color: var(--color-primary);
  letter-spacing: -0.025em;
}

.header-actions {
  position: relative;
  display: flex;
  align-items: center;
  gap: var(--space-2);
}

.desktop-only { display: none; }
.mobile-only { display: flex; }

@media (min-width: 768px) {
  .desktop-only { display: flex; }
  .mobile-only { display: none; }
}

.dropdown {
  position: absolute;
  top: 100%;
  right: 0;
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-input);
  box-shadow: var(--shadow-modal);
  min-width: 160px;
  z-index: 20;
}

.dropdown-item {
  display: block;
  width: 100%;
  padding: var(--space-3) var(--space-4);
  text-align: left;
  font-size: var(--fs-body);
  cursor: pointer;
  background: none;
  border: none;
}

.dropdown-item:hover {
  background: var(--color-bg);
}
</style>
