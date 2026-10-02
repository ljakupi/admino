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
 */
import { computed } from 'vue';
import { Building2 } from 'lucide-vue-next';
import EmptyState from '@/components/EmptyState.vue';
import PermissionMatrix from '@/components/PermissionMatrix.vue';
import CriticalPermissionsCard from '@/components/CriticalPermissionsCard.vue';
import OrgServicesCard from '@/components/OrgServicesCard.vue';
import { useAuthStore } from '@/stores/auth';
import { canManageOrgPermissions, canManageOrgSettings } from '@/services/access';
import { t } from '@/i18n';

const auth = useAuthStore();
const canManage = computed(() => canManageOrgPermissions(auth.role));
const canManageServices = computed(() => canManageOrgSettings(auth.role));
</script>

<template>
  <div class="organization-page">
    <template v-if="canManage">
      <header class="page-header">
        <h1>{{ t('nav.organization') }}</h1>
      </header>
      <div class="page-content">
        <OrgServicesCard v-if="canManageServices" />
        <PermissionMatrix />
        <CriticalPermissionsCard />
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
}

.page-content {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
  max-width: 720px;
  margin: 0 auto;
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 28px;
}
</style>
