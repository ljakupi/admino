<script setup lang="ts">
import { ref } from 'vue';
import {
  Mail, Calendar, HardDrive, FileText, Search, Brain, Plug,
} from 'lucide-vue-next';
import ToolGroupCard from '@/components/ToolGroupCard.vue';
import ConfirmSheet from '@/components/ConfirmSheet.vue';

interface ToolGroup {
  id: string;
  name: string;
  description: string;
  icon: typeof Mail;
  enabled: boolean;
  connected: boolean;
  locked?: boolean;
}

const tools = ref<ToolGroup[]>([
  { id: 'gmail', name: 'Gmail', description: 'Read, search your Gmail inbox', icon: Mail, enabled: true, connected: true },
  { id: 'google_calendar', name: 'Google Calendar', description: 'Read, list, create calendar events', icon: Calendar, enabled: true, connected: true },
  { id: 'google_drive', name: 'Google Drive', description: 'Read, list, search, download files', icon: HardDrive, enabled: true, connected: true },
  { id: 'outlook', name: 'Outlook Mail', description: 'Read, search your Outlook inbox', icon: Mail, enabled: true, connected: false },
  { id: 'outlook_calendar', name: 'Outlook Calendar', description: 'Read, list, create calendar events', icon: Calendar, enabled: true, connected: false },
  { id: 'onedrive', name: 'OneDrive', description: 'Read, list, search, download files', icon: HardDrive, enabled: true, connected: false },
  { id: 'documents', name: 'Documents', description: 'Store, classify, search, query local documents', icon: FileText, enabled: true, connected: true },
  { id: 'files', name: 'Files', description: 'Read, list, search, write local files', icon: FileText, enabled: true, connected: true },
  { id: 'web_search', name: 'Web Search', description: 'Search the web', icon: Search, enabled: false, connected: true },
  { id: 'memory', name: 'Memory', description: 'Persistent key-value notes', icon: Brain, enabled: true, connected: true },
]);

const confirmToggle = ref<{ tool: ToolGroup; newValue: boolean } | null>(null);

function handleToggle(tool: ToolGroup, value: boolean) {
  if (!value) {
    confirmToggle.value = { tool, newValue: value };
  } else {
    tool.enabled = value;
  }
}

function confirmDisable() {
  if (confirmToggle.value) {
    confirmToggle.value.tool.enabled = confirmToggle.value.newValue;
    confirmToggle.value = null;
  }
}
</script>

<template>
  <div class="tools-page">
    <header class="page-header">
      <h1>Tools</h1>
    </header>
    <div class="page-content">
      <div class="tools-grid">
        <ToolGroupCard
          v-for="tool in tools"
          :key="tool.id"
          :icon="tool.icon"
          :name="tool.name"
          :description="tool.description"
          :enabled="tool.enabled"
          :connected="tool.connected"
          :locked="tool.locked"
          @toggle="handleToggle(tool, $event)"
        />
      </div>
    </div>

    <ConfirmSheet
      v-if="confirmToggle"
      :heading="`Disable ${confirmToggle.tool.name}?`"
      :subtext="`The agent will no longer be able to use ${confirmToggle.tool.name}.`"
      confirm-label="Disable"
      variant="destructive"
      @confirm="confirmDisable"
      @cancel="confirmToggle = null"
    />
  </div>
</template>

<style scoped>
.tools-page {
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
}

.tools-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: var(--space-3);
  max-width: var(--content-max);
  margin: 0 auto;
}

@media (min-width: 600px) {
  .tools-grid {
    grid-template-columns: 1fr 1fr;
  }
}
</style>
