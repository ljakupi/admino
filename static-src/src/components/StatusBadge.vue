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

/** Map status to badge variant class */
const variantMap: Record<string, string> = {
  approved: 'leaf',
  allowed: 'leaf',
  denied: 'clay',
  'hardcoded-deny': 'locked',
  pending: 'amber',
  confirm: 'amber',
};
</script>

<template>
  <span class="badge" :class="variantMap[props.status]">
    <Lock v-if="props.status === 'hardcoded-deny'" :size="12" :stroke-width="2" class="lock-icon" />
    <span v-else class="dot" />
    {{ labelMap[props.status] }}
  </span>
</template>

<style scoped>
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 20px;
  font-family: var(--font-body);
  font-size: 12px;
  font-weight: 500;
  border: 1px solid transparent;
  white-space: nowrap;
}

.dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}

/* Leaf — Approved, Allowed, Connected */
.leaf {
  background: #DCF8C6;
  color: #1F5C2F;
  border-color: #BFE6A3;
}
.leaf .dot { background: #25D366; }

/* Amber — Awaiting approval, Pending */
.amber {
  background: #FFF4DC;
  color: #8A5A14;
  border-color: #F1D495;
}
.amber .dot { background: #E9A23B; }

/* Clay — Denied, Error */
.clay {
  background: #FCE4E4;
  color: #8A2A2A;
  border-color: #F0BFBF;
}
.clay .dot { background: #E35353; }

/* Locked — Hardcoded deny (neutral, immutable) */
.locked {
  background: #FFFFFF;
  color: #475560;
  border-color: #CFC7B4;
}
.locked .lock-icon { color: #667781; }
</style>
