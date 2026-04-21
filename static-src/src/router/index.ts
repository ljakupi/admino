import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import ChatPage from '@/pages/ChatPage.vue';

const routes: RouteRecordRaw[] = [
  { path: '/', redirect: '/chat' },
  { path: '/chat', name: 'chat', component: ChatPage },
  { path: '/activity', name: 'activity', component: () => import('@/pages/ActivityPage.vue') },
  { path: '/tools', name: 'tools', component: () => import('@/pages/ToolsPage.vue') },
  { path: '/permissions', name: 'permissions', component: () => import('@/pages/PermissionsPage.vue') },
  { path: '/settings', name: 'settings', component: () => import('@/pages/SettingsPage.vue') },
  { path: '/:pathMatch(.*)*', redirect: '/chat' },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;
