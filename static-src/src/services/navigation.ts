/**
 * Top-level page navigation for the app shell (issue #15; issue #144: labels
 * are translated).
 *
 * `NAV_ITEMS` is the single list of top-level pages rendered by both the
 * desktop nav rail and the mobile bottom tab bar, so the two never drift
 * out of sync. Each entry's `to` must match a named route in the router.
 * `labelKey` is a catalog key (not a hardcoded string): components render
 * `t(item.labelKey)` so the label follows the active locale reactively.
 */
import type { Component } from 'vue';
import { MessageCircle, Plug, Shield, Settings } from 'lucide-vue-next';
import type { MessageKey } from '@/i18n';

export interface NavItem {
  to: string;
  labelKey: MessageKey;
  icon: Component;
}

export const NAV_ITEMS: readonly NavItem[] = [
  { to: '/chat', labelKey: 'nav.chat', icon: MessageCircle },
  { to: '/tools', labelKey: 'nav.tools', icon: Plug },
  { to: '/permissions', labelKey: 'nav.permissions', icon: Shield },
  { to: '/settings', labelKey: 'nav.settings', icon: Settings },
];
