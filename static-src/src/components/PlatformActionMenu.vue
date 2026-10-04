<script setup lang="ts">
/**
 * Small "..." action menu used by the Platform console rows (issue #168).
 * Purely presentational: the parent passes the already-labelled items
 * (derived from the services' `orgActions` / `userActions`) and handles
 * `select`.
 */
import { ref } from 'vue';
import { MoreVertical } from 'lucide-vue-next';
import IconButton from '@/components/IconButton.vue';

export interface ActionMenuItem {
  key: string;
  label: string;
  destructive?: boolean;
}

defineProps<{
  items: ActionMenuItem[];
  label: string;
}>();

const emit = defineEmits<{
  select: [key: string];
}>();

const open = ref(false);

function choose(key: string): void {
  open.value = false;
  emit('select', key);
}
</script>

<template>
  <div v-if="items.length > 0" class="action-menu">
    <IconButton :aria-label="label" :title="label" @click.stop="open = !open">
      <MoreVertical :size="18" :stroke-width="1.75" />
    </IconButton>
    <template v-if="open">
      <div class="menu-backdrop" @click.stop="open = false" />
      <ul class="menu" role="menu">
        <li v-for="item in items" :key="item.key" role="none">
          <button
            type="button"
            role="menuitem"
            class="menu-item"
            :class="{ destructive: item.destructive }"
            @click.stop="choose(item.key)"
          >
            {{ item.label }}
          </button>
        </li>
      </ul>
    </template>
  </div>
</template>

<style scoped>
.action-menu {
  position: relative;
}

.menu-backdrop {
  position: fixed;
  inset: 0;
  z-index: 40;
}

.menu {
  position: absolute;
  right: 0;
  top: 100%;
  z-index: 41;
  min-width: 200px;
  margin: 4px 0 0;
  padding: 4px;
  list-style: none;
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  box-shadow: var(--shadow-modal);
}

.menu-item {
  display: block;
  width: 100%;
  min-height: 44px;
  padding: 10px 12px;
  text-align: left;
  font-family: inherit;
  font-size: 14px;
  background: transparent;
  border: 0;
  border-radius: 6px;
  color: var(--color-text);
  cursor: pointer;
}

.menu-item:hover {
  background: var(--color-bg-surface);
}

.menu-item.destructive {
  color: var(--color-error);
}
</style>
