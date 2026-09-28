/**
 * Top-level page navigation for the app shell (issue #15; issue #144: labels
 * are translated; issue #155: the shell is role-aware).
 *
 * `NAV_ITEMS` is the single, ordered list of every top-level area, rendered
 * by both the desktop nav rail and the mobile bottom tab bar, so the two
 * never drift out of sync. Each entry's `to` must match a named route in the
 * router whose `meta.area` equals the entry's `area`. `navItemsFor(role)`
 * filters the list by the role matrix (`@/services/access`) while keeping
 * the order, so a role only ever sees the areas it may open.
 */
import type { Component } from 'vue';
import { Building2, MessageCircle, Plug, Server, Settings, Shield } from 'lucide-vue-next';
import { canAccessArea, type Area, type ShellRole } from './access';
import type { MessageKey } from '@/i18n';

export interface NavItem {
  to: string;
  labelKey: MessageKey;
  icon: Component;
  area: Area;
}

export const NAV_ITEMS: readonly NavItem[] = [
  { to: '/chat', labelKey: 'nav.chat', icon: MessageCircle, area: 'chat' },
  { to: '/tools', labelKey: 'nav.tools', icon: Plug, area: 'tools' },
  { to: '/permissions', labelKey: 'nav.permissions', icon: Shield, area: 'permissions' },
  { to: '/organization', labelKey: 'nav.organization', icon: Building2, area: 'organization' },
  { to: '/settings', labelKey: 'nav.settings', icon: Settings, area: 'settings' },
  { to: '/platform', labelKey: 'nav.platform', icon: Server, area: 'platform' },
];

/** `NAV_ITEMS` filtered to the areas `role` may open, in `NAV_ITEMS` order. Logged out (`null`) sees nothing. */
export function navItemsFor(role: ShellRole | null): readonly NavItem[] {
  return NAV_ITEMS.filter((item) => canAccessArea(role, item.area));
}
