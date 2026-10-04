<script setup lang="ts">
/**
 * Organization console (issue #161): the Org Admin's permission matrix and
 * critical permissions, moved here from the (now read-only, Editor/Viewer)
 * Permissions page. The route guard already keeps every other role out of
 * `/organization` (`services/access.ts` area matrix), `canManageOrgPermissions`
 * is a defense-in-depth check only.
 *
 * Issue #162: the Org Admin's per-service switches move here too
 * (`OrgServicesCard.vue`), gated the same way by `canManageOrgSettings`.
 *
 * Issue #169: the services card moved into the Settings tab
 * (`OrgSettingsPanel.vue`); Permissions keeps the matrix and critical card.
 *
 * Issue #165: a Users tab (`OrgUsersPanel.vue`) joins the Permissions
 * tab. The active tab is driven by the `?tab=` query
 * (`services/orgUsers.ts`'s `orgTabFrom`, Users is the default) so the tab
 * survives a reload or a shared link; switching tabs updates the query with
 * `router.replace` (no new history entry).
 */
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Building2 } from 'lucide-vue-next';
import EmptyState from '@/components/EmptyState.vue';
import PermissionMatrix from '@/components/PermissionMatrix.vue';
import CriticalPermissionsCard from '@/components/CriticalPermissionsCard.vue';
import OrgUsersPanel from '@/components/OrgUsersPanel.vue';
import OrgSettingsPanel from '@/components/OrgSettingsPanel.vue';
import { useAuthStore } from '@/stores/auth';
import { canManageOrgPermissions } from '@/services/access';
import { orgTabFrom, type OrgTab } from '@/services/orgUsers';
import { t } from '@/i18n';

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const canManage = computed(() => canManageOrgPermissions(auth.role));
const activeTab = computed<OrgTab>(() => orgTabFrom(route.query.tab));

function selectTab(tab: OrgTab): void {
  if (tab === activeTab.value) return;
  void router.replace({ query: { ...route.query, tab } });
}
</script>

<template>
  <div class="organization-page">
    <template v-if="canManage">
      <header class="page-header">
        <h1>{{ t('nav.organization') }}</h1>
        <div class="tabs" role="tablist">
          <button
            type="button"
            role="tab"
            class="tab-btn"
            :class="{ on: activeTab === 'users' }"
            :aria-selected="activeTab === 'users'"
            @click="selectTab('users')"
          >
            {{ t('organization.tabs.users') }}
          </button>
          <button
            type="button"
            role="tab"
            class="tab-btn"
            :class="{ on: activeTab === 'settings' }"
            :aria-selected="activeTab === 'settings'"
            @click="selectTab('settings')"
          >
            {{ t('organization.tabs.settings') }}
          </button>
          <button
            type="button"
            role="tab"
            class="tab-btn"
            :class="{ on: activeTab === 'permissions' }"
            :aria-selected="activeTab === 'permissions'"
            @click="selectTab('permissions')"
          >
            {{ t('organization.tabs.permissions') }}
          </button>
        </div>
      </header>
      <div class="page-content">
        <OrgUsersPanel v-if="activeTab === 'users'" />
        <OrgSettingsPanel v-else-if="activeTab === 'settings'" @open-permissions="selectTab('permissions')" />
        <template v-else>
          <PermissionMatrix />
          <CriticalPermissionsCard />
        </template>
      </div>
    </template>
    <EmptyState
      v-else
      :icon="Building2"
      :heading="t('organization.empty.heading')"
      :subtext="t('organization.empty.subtext')"
    />
  </div>
</template>

<style scoped>
.organization-page {
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

.page-header h1 {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 20px;
  letter-spacing: -0.02em;
  color: var(--color-text);
  margin-bottom: var(--space-3);
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
  max-width: 960px;
  margin: 0 auto;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 28px;
}
</style>
