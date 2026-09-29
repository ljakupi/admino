<script setup lang="ts">
import { Building2 } from 'lucide-vue-next';
import EmptyState from '@/components/EmptyState.vue';
import { t } from '@/i18n';
</script>

<template>
  <div class="organization-page">
    <EmptyState :icon="Building2" :heading="t('organization.empty.heading')" :subtext="t('organization.empty.subtext')" />
  </div>
</template>

<style scoped>
.organization-page {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}
</style>
