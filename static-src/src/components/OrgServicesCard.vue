<script setup lang="ts">
/**
 * Organization console's services card (issue #162): the Org Admin's seven
 * tool switches, moved here from the Tools page. Google/Microsoft rows are
 * disabled under the org's data residency policy (`useOrgServicesStore`);
 * `memory` is never locked.
 */
import { computed, onMounted } from 'vue';
import { Mail, Calendar, Folder, Brain } from 'lucide-vue-next';
import BaseToggle from '@/components/BaseToggle.vue';
import { useOrgServicesStore } from '@/stores/orgServices';
import type { ToolsSettings } from '@/api/types';
import { useI18n, type MessageKey } from '@/i18n';

const { t } = useI18n();
const store = useOrgServicesStore();

onMounted(() => store.load());

interface ServiceDef {
  id: keyof ToolsSettings;
  icon: typeof Mail;
  nameKey: MessageKey;
}

const SERVICES: readonly ServiceDef[] = [
  { id: 'gmail', icon: Mail, nameKey: 'tools.gmail.label' },
  { id: 'google_calendar', icon: Calendar, nameKey: 'tools.googleCalendar.label' },
  { id: 'google_drive', icon: Folder, nameKey: 'tools.googleDrive.label' },
  { id: 'outlook', icon: Mail, nameKey: 'toolsPage.service.outlookMail' },
  { id: 'outlook_calendar', icon: Calendar, nameKey: 'tools.outlookCalendar.label' },
  { id: 'onedrive', icon: Folder, nameKey: 'tools.onedrive.label' },
  { id: 'memory', icon: Brain, nameKey: 'tools.memory.label' },
];

const residencyLocked = computed(() => store.dataResidency);

function onToggle(tool: keyof ToolsSettings, enabled: boolean) {
  store.setEnabled(tool, enabled);
}
</script>

<template>
  <section class="services-card">
    <div class="section-head">
      <h2 class="section-title">{{ t('organization.services.title') }}</h2>
      <p class="section-sub">{{ t('organization.services.subtitle') }}</p>
    </div>

    <p v-if="residencyLocked" class="residency-note">
      {{ t('organization.services.residencyLocked') }}
    </p>

    <div class="services-list">
      <div v-for="svc in SERVICES" :key="svc.id" class="service-row">
        <component :is="svc.icon" class="service-icon" :size="20" :stroke-width="1.75" />
        <div class="service-info">
          <span class="service-name">{{ t(svc.nameKey) }}</span>
        </div>
        <BaseToggle
          :model-value="store.tools[svc.id]"
          :disabled="store.isLocked(svc.id)"
          :aria-label="t(svc.nameKey)"
          @update:model-value="onToggle(svc.id, $event)"
        />
      </div>
    </div>
  </section>
</template>

<style scoped>
.services-card {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.section-head {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.section-title {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 18px;
  letter-spacing: -0.015em;
  color: var(--color-text);
}

.section-sub {
  font-size: 13px;
  color: var(--color-text-muted);
}

.residency-note {
  padding: 10px 14px;
  border-radius: var(--radius-input);
  font-size: 12.5px;
  color: #8A5A14;
  background: var(--color-warn-soft);
  border: 1px solid #F1D495;
}

.services-list {
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: 12px;
  overflow: hidden;
}

.service-row {
  display: grid;
  grid-template-columns: 28px 1fr auto;
  gap: 14px;
  align-items: center;
  padding: 14px 20px;
  min-height: 44px;
}

.service-row + .service-row {
  border-top: 1px solid var(--color-border);
}

.service-icon {
  color: var(--color-primary-mid);
  display: flex;
  align-items: center;
}

.service-info {
  display: flex;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
}

.service-name {
  font-weight: var(--fw-semibold);
  font-size: 14px;
  color: var(--color-text);
}
</style>
