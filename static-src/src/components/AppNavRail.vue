<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router';
import { computed } from 'vue';
import { LogOut } from 'lucide-vue-next';
import IconButton from './IconButton.vue';
import { useAuthStore } from '@/stores/auth';
import { useChatStore } from '@/stores/chat';
import { navItemsFor } from '@/services/navigation';
import { t } from '@/i18n';

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const chatStore = useChatStore();

const pendingCount = computed(() =>
  chatStore.pendingConfirmation ? 1 : 0,
);

const navItems = computed(() => navItemsFor(auth.role));

async function onLogout(): Promise<void> {
  await auth.logout();
  await router.replace('/login');
}
</script>

<template>
  <nav class="nav-rail" :aria-label="t('nav.mainNavigation')">
    <div class="nav-logo">a</div>
    <div class="nav-items">
      <RouterLink
        v-for="item in navItems"
        :key="item.to"
        :to="item.to"
        class="nav-item"
        :class="{ active: route.path.startsWith(item.to) }"
        :aria-label="t(item.labelKey)"
        :title="t(item.labelKey)"
      >
        <span class="nav-icon-wrap">
          <component :is="item.icon" :size="20" :stroke-width="1.75" />
          <span
            v-if="item.to === '/chat' && pendingCount > 0"
            class="badge"
          />
        </span>
      </RouterLink>
    </div>
    <div class="nav-footer">
      <IconButton :aria-label="t('nav.logout')" :title="t('nav.logout')" @click="onLogout">
        <LogOut :size="20" :stroke-width="1.75" />
      </IconButton>
    </div>
  </nav>
</template>

<style scoped>
.nav-rail {
  width: var(--nav-rail-w);
  min-width: var(--nav-rail-w);
  height: 100dvh;
  background: var(--color-bg-surface);
  border-right: 1px solid var(--color-border);
  flex-direction: column;
  align-items: center;
  padding: var(--space-4) 0;
  gap: var(--space-2);
}

.nav-logo {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 22px;
  color: var(--color-primary);
  margin-bottom: var(--space-6);
  user-select: none;
}

.nav-items {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-1);
}

.nav-item {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 44px;
  height: 44px;
  border-radius: var(--radius-card);
  color: var(--color-text-muted);
  transition: var(--transition-hover);
}

.nav-item:hover {
  color: var(--color-text);
  background: var(--color-border);
}

.nav-item.active {
  color: var(--color-text-on-dark);
  background: var(--color-primary);
}

.nav-icon-wrap {
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

.nav-footer {
  margin-top: auto;
}
</style>
