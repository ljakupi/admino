<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue';
import { ShieldAlert, Mail, Calendar, Clock, Check, Info } from 'lucide-vue-next';
import ReAuthDialog from './ReAuthDialog.vue';
import {
  useCriticalPermissionsStore,
  CRIT_PERMS,
  COOLDOWN_SEC,
  type CritPermDef,
} from '@/stores/criticalPermissions';

const store = useCriticalPermissionsStore();

const ICON_MAP: Record<string, typeof Mail> = {
  mail: Mail,
  calendar: Calendar,
};

// --- Cooldown timer ---
const now = ref(Date.now());
let timerId: ReturnType<typeof setInterval> | null = null;

const hasPending = computed(() =>
  CRIT_PERMS.some(p => {
    const s = store.getState(p.tool, p.action);
    if (!s.pendingAt) return false;
    const remaining = COOLDOWN_SEC - Math.floor((now.value - s.pendingAt) / 1000);
    return remaining > 0;
  }),
);

function startTimer() {
  if (timerId) return;
  timerId = setInterval(() => { now.value = Date.now(); }, 1000);
}

function stopTimer() {
  if (timerId) {
    clearInterval(timerId);
    timerId = null;
  }
}

watch(hasPending, (val) => {
  if (val) startTimer();
  else {
    stopTimer();
    // Refetch to sync server state after cooldown expiry
    store.load();
  }
}, { immediate: true });

onMounted(() => {
  store.load();
});

onUnmounted(() => {
  stopTimer();
});

// --- Helpers ---
function remaining(pendingAt: number | null): number {
  if (!pendingAt) return 0;
  return Math.max(0, COOLDOWN_SEC - Math.floor((now.value - pendingAt) / 1000));
}

function formatTime(secs: number): string {
  const m = Math.floor(secs / 60);
  const s = String(secs % 60).padStart(2, '0');
  return `${m}:${s}`;
}

function isPending(tool: string, action: string): boolean {
  const s = store.getState(tool, action);
  return Boolean(s.pendingAt) && remaining(s.pendingAt) > 0;
}

function isOn(tool: string, action: string): boolean {
  const s = store.getState(tool, action);
  return s.state === 'confirm' && !isPending(tool, action);
}

function rowClass(tool: string, action: string): string {
  const on = isOn(tool, action);
  const pending = isPending(tool, action);
  return `crit-row${on ? ' is-on' : ''}${pending ? ' is-pending' : ''}`;
}

function toggleClass(tool: string, action: string): string {
  const on = isOn(tool, action);
  const pending = isPending(tool, action);
  return `crit-toggle${on ? ' on' : ''}${pending ? ' on pending' : ''}`;
}

function handleToggle(row: CritPermDef) {
  if (isOn(row.tool, row.action) || isPending(row.tool, row.action)) {
    store.demote(row.tool, row.action);
  } else {
    store.openAuth(row);
  }
}

async function handleAuthConfirm(token: string) {
  if (!store.authRow) return;
  const { tool, action } = store.authRow;
  try {
    await store.promote(tool, action, token);
    store.closeAuth();
  } catch {
    // Toast already shown by store; keep dialog open for retry
  }
}
</script>

<template>
  <div class="crit-card">
    <div class="crit-head">
      <div class="crit-head-icon">
        <ShieldAlert :size="16" :stroke-width="1.75" />
      </div>
      <div>
        <div class="crit-head-title">Critical Permissions</div>
        <div class="crit-head-sub">
          Allow the agent to propose these actions. You will still approve each one individually before it executes.
        </div>
      </div>
    </div>

    <div class="crit-rows">
      <div
        v-for="row in CRIT_PERMS"
        :key="`${row.tool}.${row.action}`"
        :class="rowClass(row.tool, row.action)"
      >
        <div class="crit-row-icon">
          <component :is="ICON_MAP[row.icon]" :size="18" :stroke-width="1.75" />
        </div>
        <div class="crit-row-main">
          <div class="crit-row-head">
            <span class="crit-row-label">{{ row.label }}</span>
            <code class="crit-row-id">{{ row.tool }}.{{ row.action }}</code>
          </div>
          <div class="crit-row-desc">{{ row.description }}</div>

          <!-- Pending state -->
          <div v-if="isPending(row.tool, row.action)" class="crit-pending-line">
            <span class="crit-pending-badge">
              <Clock :size="11" :stroke-width="2" />
              Active in {{ formatTime(remaining(store.getState(row.tool, row.action).pendingAt)) }}
            </span>
            <button class="crit-pending-cancel" @click="store.cancelPending(row.tool, row.action)">
              Cancel
            </button>
          </div>

          <!-- Active state -->
          <div v-else-if="isOn(row.tool, row.action)" class="crit-active-line">
            <span class="crit-active-badge">
              <Check :size="10" :stroke-width="2" />
              Active
            </span>
            <span class="crit-active-aux">admino will ask you before each {{ row.action }}</span>
          </div>
        </div>

        <div class="crit-row-toggle">
          <button
            role="switch"
            :class="toggleClass(row.tool, row.action)"
            :aria-checked="isOn(row.tool, row.action) || isPending(row.tool, row.action)"
            :aria-label="`Toggle ${row.label}`"
            @click="handleToggle(row)"
          >
            <span class="crit-toggle-thumb" />
          </button>
        </div>
      </div>
    </div>

    <div class="crit-foot">
      <Info :size="12" :stroke-width="2" />
      <span>Disabling takes effect immediately. Enabling requires re-authentication and a 5-minute cooldown you can cancel.</span>
    </div>
  </div>

  <ReAuthDialog
    v-if="store.authRow"
    :tool="store.authRow.tool"
    :action="store.authRow.action"
    :label="store.authRow.label"
    @confirm="handleAuthConfirm"
    @cancel="store.closeAuth()"
  />
</template>

<style scoped>
/* ── Card shell ── */
.crit-card {
  background: var(--color-bg-elevated);
  border: 1px solid #F1D495;
  border-radius: 12px;
  overflow: hidden;
}

/* ── Header ── */
.crit-head {
  display: grid;
  grid-template-columns: 32px 1fr;
  gap: 12px;
  align-items: flex-start;
  padding: 16px 20px;
  background: linear-gradient(180deg, #FFF8EA, var(--color-bg-surface));
  border-bottom: 1px solid #F1D495;
}

.crit-head-icon {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: var(--color-warn-soft);
  border: 1px solid #F1D495;
  color: #B58127;
  display: grid;
  place-items: center;
}

.crit-head-title {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 15px;
  letter-spacing: -0.01em;
  color: #5B3E0F;
}

.crit-head-sub {
  font-size: 12.5px;
  color: #8A5A14;
  margin-top: 3px;
  line-height: 1.5;
}

/* ── Rows ── */
.crit-rows {
  display: flex;
  flex-direction: column;
}

.crit-row {
  display: grid;
  grid-template-columns: 36px 1fr auto;
  gap: 14px;
  align-items: flex-start;
  padding: 14px 20px;
  border-bottom: 1px solid #F4ECD7;
  transition: background 0.15s;
}

.crit-row:last-child {
  border-bottom: 0;
}

.crit-row.is-on:not(.is-pending) {
  background: linear-gradient(0deg, rgba(37, 211, 102, 0.04), rgba(37, 211, 102, 0.04));
}

.crit-row.is-pending {
  background: linear-gradient(0deg, rgba(233, 162, 59, 0.08), rgba(233, 162, 59, 0.08));
}

/* ── Row icon ── */
.crit-row-icon {
  width: 36px;
  height: 36px;
  border-radius: 8px;
  background: #F5F7F5;
  border: 1px solid var(--color-border);
  color: var(--color-primary-mid);
  display: grid;
  place-items: center;
  margin-top: 2px;
}

.crit-row.is-on:not(.is-pending) .crit-row-icon {
  background: var(--color-accent-soft);
  border-color: #BFE6A3;
  color: #1F5C2F;
}

.crit-row.is-pending .crit-row-icon {
  background: var(--color-warn-soft);
  border-color: #F1D495;
  color: #B58127;
}

/* ── Row content ── */
.crit-row-main {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}

.crit-row-head {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.crit-row-label {
  font-weight: var(--fw-semibold);
  font-size: 14px;
  color: var(--color-text);
}

.crit-row-id {
  font-family: var(--font-mono);
  font-size: 11px;
  background: #F5F7F5;
  color: var(--color-text-muted);
  padding: 1px 6px;
  border-radius: 4px;
  border: 1px solid var(--color-border);
}

.crit-row-desc {
  font-size: 12.5px;
  color: #475560;
  line-height: 1.5;
}

/* ── Status badges ── */
.crit-pending-line,
.crit-active-line {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  margin-top: 4px;
}

.crit-pending-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 9px;
  background: var(--color-warn-soft);
  border: 1px solid #F1D495;
  border-radius: 10px;
  color: #8A5A14;
  font-size: 11.5px;
  font-weight: var(--fw-semibold);
  font-variant-numeric: tabular-nums;
}

.crit-pending-cancel {
  all: unset;
  font-size: 12px;
  font-weight: var(--fw-medium);
  color: var(--color-primary-mid);
  cursor: pointer;
  text-decoration: underline;
  text-underline-offset: 2px;
}

.crit-pending-cancel:hover {
  color: var(--color-primary);
}

.crit-active-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  background: var(--color-accent-soft);
  border: 1px solid #BFE6A3;
  border-radius: 10px;
  color: #1F5C2F;
  font-size: 11px;
  font-weight: var(--fw-semibold);
}

.crit-active-aux {
  font-size: 11.5px;
  color: var(--color-text-muted);
}

/* ── Toggle ── */
.crit-row-toggle {
  display: flex;
  align-items: center;
  padding-top: 4px;
}

.crit-toggle {
  position: relative;
  width: 36px;
  height: 20px;
  background: var(--color-border-strong);
  border-radius: 12px;
  cursor: pointer;
  border: 0;
  padding: 0;
  transition: background 0.15s;
  flex-shrink: 0;
}

.crit-toggle-thumb {
  position: absolute;
  top: 2px;
  left: 2px;
  width: 16px;
  height: 16px;
  background: #fff;
  border-radius: 50%;
  box-shadow: 0 1px 2px rgba(17, 27, 33, 0.18);
  transition: transform 0.15s;
}

.crit-toggle.on {
  background: var(--color-primary);
}

.crit-toggle.on .crit-toggle-thumb {
  transform: translateX(16px);
}

.crit-toggle.pending {
  background: var(--color-warn);
  background-image: repeating-linear-gradient(
    45deg,
    rgba(255, 255, 255, 0.22) 0 4px,
    transparent 4px 8px
  );
}

/* ── Footer ── */
.crit-foot {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background: var(--color-bg-surface);
  border-top: 1px solid #F4ECD7;
  font-size: 11.5px;
  color: #8A5A14;
  line-height: 1.5;
}

.crit-foot svg {
  flex-shrink: 0;
  color: #B58127;
}
</style>
