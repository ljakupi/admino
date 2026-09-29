<script setup lang="ts">
import { LogOut, Server } from 'lucide-vue-next';
import { useRouter } from 'vue-router';
import BaseButton from '@/components/BaseButton.vue';
import EmptyState from '@/components/EmptyState.vue';
import { useAuthStore } from '@/stores/auth';
import { t } from '@/i18n';

const router = useRouter();
const auth = useAuthStore();

async function onLogout(): Promise<void> {
  await auth.logout();
  await router.replace('/login');
}
</script>

<template>
  <div class="platform-page">
    <EmptyState :icon="Server" :heading="t('platform.empty.heading')" :subtext="t('platform.empty.subtext')">
      <BaseButton variant="secondary" @click="onLogout">
        <LogOut :size="16" :stroke-width="1.75" />
        {{ t('nav.logout') }}
      </BaseButton>
    </EmptyState>
  </div>
</template>

<style scoped>
.platform-page {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}
</style>
