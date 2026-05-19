<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { Lock, ShieldAlert } from 'lucide-vue-next';
import type { PermissionState } from '@/api/types';

const props = withDefaults(defineProps<{
  permission: PermissionState;
  hardcoded?: boolean;
  promotable?: boolean;
  saving?: boolean;
}>(), {
  hardcoded: false,
  promotable: false,
  saving: false,
});

const router = useRouter();

const emit = defineEmits<{
  change: [permission: PermissionState];
}>();

const open = ref(false);

function toggle() {
  if (props.hardcoded || props.saving) return;
  if (props.promotable) {
    router.push({ path: '/settings', hash: '#danger' });
    return;
  }
  open.value = !open.value;
}

function select(perm: PermissionState) {
  open.value = false;
  if (perm !== props.permission) {
    emit('change', perm);
  }
}

function closeDropdown() {
  open.value = false;
}

const options: { value: PermissionState; label: string }[] = [
  { value: 'allow', label: 'Allowed' },
  { value: 'confirm', label: 'Needs approval' },
  { value: 'deny', label: 'Denied' },
];
</script>

<template>
  <div class="pill-wrap">
    <!-- Transparent overlay to close dropdown on outside click -->
    <div v-if="open" class="overlay" @click="closeDropdown" />

    <button
      class="pill"
      :class="[permission, { hardcoded, promotable, saving }]"
      :title="promotable
        ? 'This permission can be managed from Settings \u203a Danger Zone'
        : hardcoded
          ? 'This permission is enforced by security policy and cannot be changed'
          : undefined"
      :style="saving ? 'opacity: 0.5; cursor: wait;' : undefined"
      @click="toggle"
    >
      <ShieldAlert v-if="promotable" :size="11" :stroke-width="2" />
      <Lock v-else-if="hardcoded" :size="11" :stroke-width="2" />
      <span class="dot" />
      <span class="label">{{ (hardcoded || promotable) ? 'Denied' : options.find(o => o.value === permission)?.label }}</span>
    </button>

    <div v-if="open" class="dropdown">
      <button
        v-for="opt in options"
        :key="opt.value"
        class="opt"
        :class="[opt.value, { active: opt.value === permission }]"
        @click="select(opt.value)"
      >
        <span class="dot" />
        {{ opt.label }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.pill-wrap {
  position: relative;
  display: inline-flex;
}

.overlay {
  position: fixed;
  inset: 0;
  z-index: 10;
}

.pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 10px 3px 8px;
  border-radius: 12px;
  border: 1px solid;
  font-size: 12px;
  font-weight: 500;
  font-family: inherit;
  cursor: pointer;
  white-space: nowrap;
  transition: opacity 120ms ease;
  position: relative;
  z-index: 11;
}

.pill.allow {
  background: #DCF8C6;
  color: #1F5C2F;
  border-color: #BFE6A3;
}

.pill.confirm {
  background: #FFF4DC;
  color: #8A5A14;
  border-color: #F1D495;
}

.pill.deny {
  background: #FFFFFF;
  color: #475560;
  border-color: #D6D9DB;
}

.pill.hardcoded {
  cursor: not-allowed;
  background: #FFFFFF;
  color: #475560;
  border-color: #D6D9DB;
}

.pill.promotable {
  cursor: pointer;
  background: #FFFFFF;
  color: #8A5A14;
  border-color: #F1D495;
}

.pill .dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}

.pill.allow .dot { background: #25D366; }
.pill.confirm .dot { background: #E9A23B; }
.pill.deny .dot { background: #8A9199; }
.pill.hardcoded .dot { display: none; }
.pill.promotable .dot { display: none; }

.dropdown {
  position: absolute;
  top: calc(100% + 4px);
  right: 0;
  background: #FFFFFF;
  border: 1px solid #E4E8EA;
  border-radius: 8px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
  padding: 4px;
  z-index: 12;
  min-width: 148px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.opt {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 10px;
  border-radius: 5px;
  border: 0;
  background: transparent;
  font-size: 12.5px;
  font-family: inherit;
  color: #111B21;
  cursor: pointer;
  text-align: left;
  transition: background 80ms ease;
}

.opt:hover { background: #F5F7F5; }
.opt.active { font-weight: 600; }

.opt .dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.opt.allow .dot { background: #25D366; }
.opt.confirm .dot { background: #E9A23B; }
.opt.deny .dot { background: #8A9199; }
</style>
