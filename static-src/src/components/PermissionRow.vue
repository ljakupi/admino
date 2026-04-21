<script setup lang="ts">
import StatusBadge from './StatusBadge.vue';

defineProps<{
  tool: string;
  action: string;
  status: 'allow' | 'confirm' | 'deny';
  hardcoded?: boolean;
}>();

function mapStatus(status: string, hardcoded?: boolean): 'allowed' | 'confirm' | 'denied' | 'hardcoded-deny' {
  if (hardcoded && status === 'deny') return 'hardcoded-deny';
  if (status === 'allow') return 'allowed';
  if (status === 'confirm') return 'confirm';
  return 'denied';
}
</script>

<template>
  <tr class="perm-row">
    <td class="mono">{{ tool }}</td>
    <td class="mono">{{ action }}</td>
    <td>
      <StatusBadge :status="mapStatus(status, hardcoded)" />
    </td>
  </tr>
</template>

<style scoped>
.perm-row td {
  padding: var(--space-3) var(--space-4);
  border-bottom: 1px solid var(--color-border);
  font-size: var(--fs-body);
  vertical-align: middle;
}
</style>
