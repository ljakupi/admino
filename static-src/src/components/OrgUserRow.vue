<script setup lang="ts">
/**
 * One row of the Organization console's Users tab (issue #165): the user's
 * display name, email, role (with an inline role picker limited to
 * `ASSIGNABLE_ROLES` — Viewer is never offered), status, last login and a
 * "..." menu for the remaining row actions. Purely presentational: every
 * action is forwarded as an event, `OrgUsersPanel.vue` drives the store.
 */
import { computed, ref } from 'vue';
import { MoreVertical } from 'lucide-vue-next';
import IconButton from '@/components/IconButton.vue';
import { ASSIGNABLE_ROLES, ROLE_LABEL_KEYS, displayName, isAssignableRole } from '@/services/orgUsers';
import { useI18n } from '@/i18n';
import type { MemberRole, OrgUser } from '@/api/types';

const { t, formatDate } = useI18n();

const props = defineProps<{
  user: OrgUser;
  isSelf: boolean;
}>();

const emit = defineEmits<{
  changeRole: [role: MemberRole];
  edit: [];
  deactivate: [];
  reactivate: [];
  resetPassword: [];
  forceLogout: [];
  delete: [];
}>();

const menuOpen = ref(false);
// Bumped on every role selection so the <select> remounts and falls back to
// `user.role` when the pending change is cancelled or fails (it isn't
// applied until the confirm sheet succeeds).
const roleNonce = ref(0);

const name = computed(() => displayName(props.user));

const lastLoginText = computed(() =>
  props.user.last_login_at === null
    ? t('orgUsers.neverLoggedIn')
    : t('orgUsers.lastLogin', { date: formatDate(new Date(props.user.last_login_at)) }),
);

function toggleMenu(): void {
  menuOpen.value = !menuOpen.value;
}

function closeMenu(): void {
  menuOpen.value = false;
}

function act(run: () => void): void {
  run();
  closeMenu();
}

function onRoleChange(event: Event): void {
  const value = (event.target as HTMLSelectElement).value;
  roleNonce.value += 1;
  if (isAssignableRole(value)) emit('changeRole', value);
}
</script>

<template>
  <li class="user-row">
    <div class="identity">
      <span class="name">
        {{ name }}
        <span v-if="isSelf" class="you-pill">{{ t('orgUsers.you') }}</span>
      </span>
      <span class="email caption">{{ user.email }}</span>
    </div>

    <select
      :key="`role-${user.id}-${roleNonce}`"
      class="role-select"
      :value="user.role"
      :aria-label="t('orgUsers.actions.changeRole')"
      @change="onRoleChange"
    >
      <option v-if="!isAssignableRole(user.role)" :value="user.role" disabled>
        {{ t(ROLE_LABEL_KEYS[user.role]) }}
      </option>
      <option v-for="role in ASSIGNABLE_ROLES" :key="role" :value="role">
        {{ t(ROLE_LABEL_KEYS[role]) }}
      </option>
    </select>

    <span class="status-pill" :class="user.status">
      {{ t(user.status === 'active' ? 'orgUsers.status.active' : 'orgUsers.status.deactivated') }}
    </span>

    <span class="last-login caption">{{ lastLoginText }}</span>

    <div class="menu-wrap">
      <IconButton :aria-label="t('orgUsers.actions.menu', { name })" @click="toggleMenu">
        <MoreVertical :size="18" :stroke-width="1.75" />
      </IconButton>
      <div v-if="menuOpen" class="menu" role="menu" @click.self="closeMenu">
        <button type="button" role="menuitem" @click="act(() => emit('edit'))">
          {{ t('orgUsers.actions.edit') }}
        </button>
        <button
          v-if="user.status === 'active'"
          type="button"
          role="menuitem"
          @click="act(() => emit('deactivate'))"
        >
          {{ t('orgUsers.actions.deactivate') }}
        </button>
        <button v-else type="button" role="menuitem" @click="act(() => emit('reactivate'))">
          {{ t('orgUsers.actions.reactivate') }}
        </button>
        <button
          v-if="user.status === 'active'"
          type="button"
          role="menuitem"
          @click="act(() => emit('resetPassword'))"
        >
          {{ t('orgUsers.actions.resetPassword') }}
        </button>
        <button type="button" role="menuitem" @click="act(() => emit('forceLogout'))">
          {{ t('orgUsers.actions.forceLogout') }}
        </button>
        <button type="button" role="menuitem" class="danger" @click="act(() => emit('delete'))">
          {{ t('orgUsers.actions.delete') }}
        </button>
      </div>
    </div>
  </li>
</template>

<style scoped>
.user-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 8px;
  border-bottom: 1px solid var(--color-border);
  flex-wrap: wrap;
}

.identity {
  display: flex;
  flex-direction: column;
  min-width: 160px;
  flex: 1;
}

.name {
  font-weight: var(--fw-semibold);
  color: var(--color-text);
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.you-pill {
  font-size: 10.5px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 10px;
  background: var(--color-bg-tint);
  color: var(--color-primary-press);
}

.email {
  color: var(--color-text-muted);
}

.role-select {
  min-height: 44px;
  padding: 6px 10px;
  border-radius: var(--radius-input);
  border: 1px solid var(--color-border-strong);
  background: var(--color-bg-elevated);
  color: var(--color-text);
  font-size: 13px;
}

.status-pill {
  font-size: 12px;
  font-weight: 500;
  padding: 4px 10px;
  border-radius: 20px;
  white-space: nowrap;
}

.status-pill.active {
  background: #DCF8C6;
  color: #1F5C2F;
}

.status-pill.deactivated {
  background: #FCE4E4;
  color: #8A2A2A;
}

.last-login {
  color: var(--color-text-muted);
  min-width: 140px;
}

.menu-wrap {
  position: relative;
}

.menu {
  position: absolute;
  right: 0;
  top: 100%;
  z-index: 20;
  min-width: 190px;
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  box-shadow: var(--shadow-modal);
  display: flex;
  flex-direction: column;
  padding: 6px;
}

.menu button {
  text-align: left;
  padding: 10px 12px;
  min-height: 44px;
  border-radius: 6px;
  color: var(--color-text);
  background: transparent;
}

.menu button:hover {
  background: var(--color-bg);
}

.menu button.danger {
  color: var(--color-error);
}
</style>
