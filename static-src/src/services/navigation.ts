/**
 * Top-level page navigation for the app shell (issue #15).
 *
 * `NAV_ITEMS` is the single list of top-level pages rendered by both the
 * desktop nav rail and the mobile bottom tab bar, so the two never drift
 * out of sync. Each entry's `to` must match a named route in the router.
 */
import type { Component } from 'vue';
import { MessageCircle, Plug, Shield, Settings } from 'lucide-vue-next';

export interface NavItem {
  to: string;
  label: string;
  icon: Component;
}

export const NAV_ITEMS: readonly NavItem[] = [
  { to: '/chat', label: 'Chat', icon: MessageCircle },
  { to: '/tools', label: 'Tools', icon: Plug },
  { to: '/permissions', label: 'Permissions', icon: Shield },
  { to: '/settings', label: 'Settings', icon: Settings },
];
