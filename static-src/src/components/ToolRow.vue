<script setup lang="ts">
import { ref, computed } from 'vue';
import ActionRow from './ActionRow.vue';
import { usePermissionsStore } from '@/stores/permissions';
import type { PermissionEntry } from '@/api/types';

const props = defineProps<{
  tool: string;
  entries: PermissionEntry[];
}>();

const store = usePermissionsStore();
const expanded = ref(false);

const meta = computed(() => store.getToolMeta(props.tool));
const counts = computed(() => store.toolSummary(props.tool));

function toggleExpand() {
  expanded.value = !expanded.value;
}
</script>

<template>
  <div
    class="tool"
    :aria-expanded="expanded"
    tabindex="0"
    @click="toggleExpand"
    @keydown.enter.prevent="toggleExpand"
    @keydown.space.prevent="toggleExpand"
  >
    <span class="caret">&#x25B8;</span>
    <span class="name">
      {{ meta.label }}
      <span class="desc">{{ meta.description }}</span>
    </span>
    <span class="summary">
      <span v-if="counts.allow" class="chip al"><span class="n">{{ counts.allow }}</span> allowed</span>
      <span v-if="counts.confirm" class="chip ap"><span class="n">{{ counts.confirm }}</span> approval</span>
      <span v-if="counts.deny" class="chip dn"><span class="n">{{ counts.deny }}</span> denied</span>
    </span>
    <span></span>

    <div class="actions" @click.stop>
      <ActionRow
        v-for="entry in entries"
        :key="entry.action"
        :entry="entry"
        :hardcoded="store.isHardcoded(entry.tool, entry.action)"
        :promotable="store.isPromotable(entry.tool, entry.action)"
        :saving="store.savingKey === `${entry.tool}.${entry.action}`"
        @change="(perm) => store.updatePermission(entry.tool, entry.action, perm)"
      />
    </div>
  </div>
</template>

<style scoped>
.tool {
  display: grid;
  grid-template-columns: 24px 1fr auto auto;
  column-gap: 14px;
  align-items: center;
  padding: 14px 18px;
  border-bottom: 1px solid #EEF1F2;
  cursor: pointer;
  transition: background 120ms ease;
}

.tool:last-child {
  border-bottom: 0;
}

.tool:hover {
  background: #FAFBFA;
}

.tool[aria-expanded="true"] {
  background: #FAFBFA;
}

.caret {
  font-size: 10px;
  color: #8A9199;
  transition: transform 150ms ease;
  display: inline-block;
  line-height: 1;
}

.tool[aria-expanded="true"] .caret {
  transform: rotate(90deg);
}

.name {
  font-family: 'Inter', sans-serif;
  font-weight: 600;
  font-size: 14px;
  color: #111B21;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.name .desc {
  font-weight: 400;
  font-size: 12px;
  color: #667781;
}

.summary {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11.5px;
  color: #475560;
  font-weight: 500;
}

.chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 500;
}

.chip.al {
  background: #DCF8C6;
  color: #1F5C2F;
}

.chip.ap {
  background: #FFF4DC;
  color: #8A5A14;
}

.chip.dn {
  background: #EDEFF0;
  color: #475560;
}

.chip .n {
  font-weight: 600;
}

.actions {
  grid-column: 1 / -1;
  display: none;
  padding: 6px 0 10px 38px;
  border-top: 1px dashed #E4E8EA;
  margin-top: 12px;
}

.tool[aria-expanded="true"] .actions {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
</style>
