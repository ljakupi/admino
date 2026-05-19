<script setup lang="ts">
import { computed } from 'vue';
import PermissionPill from './PermissionPill.vue';
import { usePermissionsStore } from '@/stores/permissions';
import type { PermissionEntry, PermissionState } from '@/api/types';

const props = defineProps<{
  entry: PermissionEntry;
  hardcoded: boolean;
  promotable: boolean;
  saving: boolean;
}>();

const emit = defineEmits<{
  change: [permission: PermissionState];
}>();

const store = usePermissionsStore();

const description = computed(() => store.getActionDescription(props.entry.tool, props.entry.action));
</script>

<template>
  <div class="action">
    <span class="a-name">{{ entry.action }}</span>
    <span class="a-desc">{{ description }}</span>
    <PermissionPill
      :permission="entry.permission"
      :hardcoded="hardcoded"
      :promotable="promotable"
      :saving="saving"
      @change="$emit('change', $event)"
    />
  </div>
</template>

<style scoped>
.action {
  display: grid;
  grid-template-columns: 120px 1fr auto;
  align-items: center;
  gap: 12px;
  padding: 8px 16px 8px 0;
  font-size: 13px;
}

.a-name {
  font-family: 'JetBrains Mono', 'Fira Mono', 'Cascadia Code', monospace;
  font-size: 12.5px;
  color: #111B21;
}

.a-desc {
  color: #667781;
  font-size: 12.5px;
}
</style>
