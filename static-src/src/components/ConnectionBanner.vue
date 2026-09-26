<script setup lang="ts">
import { AlertTriangle } from 'lucide-vue-next';
import BaseButton from './BaseButton.vue';
import { t } from '@/i18n';
import { useConnectionStore } from '@/stores/connection';

const connection = useConnectionStore();
</script>

<template>
  <div class="banner" role="alert">
    <AlertTriangle :size="16" :stroke-width="2" />
    <span>{{ t('connection.offlineMessage') }}</span>
    <BaseButton variant="ghost" size="md" @click="connection.checkHealth()">
      {{ t('common.retry') }}
    </BaseButton>
  </div>
</template>

<style scoped>
.banner {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-3) var(--space-4);
  background: var(--color-warn-soft);
  color: var(--color-text);
  font-size: 14px;
  border-bottom: 1px solid var(--color-warn);
}
</style>
