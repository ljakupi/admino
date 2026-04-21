<script setup lang="ts">
import { useRoute } from 'vue-router';
import { computed } from 'vue';
import { MessageCircle, Activity, Plug, Shield, Settings } from 'lucide-vue-next';
import { useChatStore } from '@/stores/chat';

const route = useRoute();
const chatStore = useChatStore();

const pendingCount = computed(() =>
  chatStore.pendingConfirmation ? 1 : 0,
);

const tabs = [
  { to: '/chat', icon: MessageCircle, label: 'Chat' },
  { to: '/activity', icon: Activity, label: 'Activity' },
  { to: '/tools', icon: Plug, label: 'Tools' },
  { to: '/permissions', icon: Shield, label: 'Permissions' },
  { to: '/settings', icon: Settings, label: 'Settings' },
];
</script>

<template>
  <nav class="tab-bar" aria-label="Main navigation">
    <RouterLink
      v-for="tab in tabs"
      :key="tab.to"
      :to="tab.to"
      class="tab"
      :class="{ active: route.path === tab.to }"
      :aria-label="tab.label"
    >
      <span class="tab-icon-wrap">
        <component :is="tab.icon" :size="20" :stroke-width="1.75" />
        <span
          v-if="tab.to === '/chat' && pendingCount > 0"
          class="badge"
        />
      </span>
      <span class="tab-label">{{ tab.label }}</span>
    </RouterLink>
  </nav>
</template>

<style scoped>
.tab-bar {
  height: var(--tabbar-h);
  background: var(--color-bg-surface);
  border-top: 1px solid var(--color-border);
  display: flex;
  align-items: center;
  justify-content: space-around;
  padding-bottom: env(safe-area-inset-bottom, 0);
}

.tab {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 2px;
  min-width: 44px;
  min-height: 44px;
  color: var(--color-text-muted);
  transition: var(--transition-hover);
  text-decoration: none;
}

.tab.active {
  color: var(--color-primary);
}

.tab-label {
  font-size: 11px;
  font-weight: var(--fw-medium);
}

.tab-icon-wrap {
  position: relative;
  display: flex;
}

.badge {
  position: absolute;
  top: -2px;
  right: -4px;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--color-error);
}
</style>
