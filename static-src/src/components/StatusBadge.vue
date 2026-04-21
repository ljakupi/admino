<script setup lang="ts">
import { Lock } from 'lucide-vue-next';

const props = defineProps<{
  status: 'approved' | 'denied' | 'pending' | 'hardcoded-deny' | 'allowed' | 'confirm';
}>();

const labelMap: Record<string, string> = {
  approved: 'Approved',
  denied: 'Denied',
  pending: 'Awaiting approval',
  'hardcoded-deny': 'Hardcoded deny',
  allowed: 'Allowed',
  confirm: 'Requires approval',
};
</script>

<template>
  <span class="badge" :class="props.status">
    <Lock v-if="props.status === 'hardcoded-deny'" :size="12" :stroke-width="2" />
    {{ labelMap[props.status] }}
  </span>
</template>

<style scoped>
.badge {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  padding: 2px var(--space-2);
  border-radius: var(--radius-pill);
  font-size: var(--fs-caption-mobile);
  font-weight: var(--fw-semibold);
  white-space: nowrap;
}

.approved, .allowed {
  background: var(--color-sage);
  color: white;
}

.denied, .hardcoded-deny {
  background: var(--color-error);
  color: white;
}

.pending, .confirm {
  background: var(--color-warn);
  color: white;
}
</style>
