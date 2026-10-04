<script setup lang="ts">
/**
 * Platform console (issue #168): the Super Admin's area with two tabs,
 * Organizations (default) and Defaults. The active tab is driven by the
 * `?tab=` query (`platformTabFrom`) and the org detail by `?org=<uuid>`
 * (`orgIdFrom`), so both survive a reload; switching tabs uses
 * `router.replace` (no new history entry), opening an org `router.push`.
 * The page only routes between panels; the logic lives in the stores.
 * Operator blindness: the console shows metadata and counts only.
 */
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { LogOut } from 'lucide-vue-next';
import BaseButton from '@/components/BaseButton.vue';
import PlatformDefaultsPanel from '@/components/PlatformDefaultsPanel.vue';
import PlatformOrgDetail from '@/components/PlatformOrgDetail.vue';
import PlatformOrgsPanel from '@/components/PlatformOrgsPanel.vue';
import { useAuthStore } from '@/stores/auth';
import { PLATFORM_TABS, orgIdFrom, platformTabFrom, type PlatformTab } from '@/services/platformOrgs';
import { t, type MessageKey } from '@/i18n';

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();

const activeTab = computed<PlatformTab>(() => platformTabFrom(route.query.tab));
const orgId = computed(() => (activeTab.value === 'orgs' ? orgIdFrom(route.query.org) : null));

const TAB_LABELS: Record<PlatformTab, MessageKey> = {
  orgs: 'platform.tabs.orgs',
  defaults: 'platform.tabs.defaults',
};

function selectTab(tab: PlatformTab): void {
  if (tab === activeTab.value && orgId.value === null) return;
  void router.replace({ query: { tab } });
}

function openOrg(id: string): void {
  void router.push({ query: { tab: 'orgs', org: id } });
}

function closeOrg(): void {
  void router.push({ query: { tab: 'orgs' } });
}

// The nav rail offers logout on desktop; the mobile bottom bar does not.
async function onLogout(): Promise<void> {
  await auth.logout();
  await router.replace('/login');
}
</script>

<template>
  <div class="platform-page">
    <header class="page-header">
      <div class="title-row">
        <h1>{{ t('platform.title') }}</h1>
        <BaseButton variant="secondary" class="mobile-logout" @click="onLogout">
          <LogOut :size="16" :stroke-width="1.75" />
          {{ t('nav.logout') }}
        </BaseButton>
      </div>
      <div class="tabs" role="tablist" :aria-label="t('platform.tabs.label')">
        <button
          v-for="tab in PLATFORM_TABS"
          :key="tab"
          type="button"
          role="tab"
          class="tab-btn"
          :class="{ on: activeTab === tab }"
          :aria-selected="activeTab === tab"
          @click="selectTab(tab)"
        >
          {{ t(TAB_LABELS[tab]) }}
        </button>
      </div>
    </header>
    <div class="page-content">
      <PlatformDefaultsPanel v-if="activeTab === 'defaults'" />
      <PlatformOrgDetail v-else-if="orgId" :org-id="orgId" @back="closeOrg" />
      <PlatformOrgsPanel v-else @open="openOrg" />
    </div>
  </div>
</template>

<style scoped>
.platform-page {
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

.title-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
  margin-bottom: var(--space-3);
}

.page-header h1 {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 20px;
  letter-spacing: -0.02em;
  color: var(--color-text);
}

@media (min-width: 768px) {
  .mobile-logout {
    display: none;
  }
}

.tabs {
  display: inline-flex;
  gap: 4px;
  padding: 3px;
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: 8px;
}

.tab-btn {
  font-family: inherit;
  font-size: 13px;
  font-weight: 500;
  padding: 8px 14px;
  min-height: 44px;
  border-radius: 6px;
  border: 0;
  background: transparent;
  color: #475560;
  cursor: pointer;
}

.tab-btn.on {
  background: #F5F7F5;
  color: var(--color-text);
}

.page-content {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
  max-width: 1040px;
  margin: 0 auto;
  width: 100%;
}
</style>
