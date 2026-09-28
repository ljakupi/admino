<script setup lang="ts">
import { onMounted, computed } from 'vue';
import { useRoute } from 'vue-router';
import AppNavRail from '@/components/AppNavRail.vue';
import BottomTabBar from '@/components/BottomTabBar.vue';
import ToastHost from '@/components/ToastHost.vue';
import ConnectionBanner from '@/components/ConnectionBanner.vue';
import { useConnectionStore } from '@/stores/connection';

const connection = useConnectionStore();
const route = useRoute();

const isPublicRoute = computed(() => route.meta.public === true);
const showOfflineBanner = computed(() => connection.state === 'offline');

onMounted(() => {
  connection.startPolling();
});
</script>

<template>
  <template v-if="isPublicRoute">
    <RouterView />
    <ToastHost />
  </template>
  <template v-else>
    <AppNavRail class="nav-rail" />
    <main class="main-content">
      <ConnectionBanner v-if="showOfflineBanner" />
      <RouterView />
    </main>
    <BottomTabBar class="bottom-bar" />
    <ToastHost />
  </template>
</template>

<style scoped>
.nav-rail {
  display: none;
}

.main-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-width: 0;
  padding-bottom: var(--tabbar-h);
}

.bottom-bar {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  z-index: 100;
}

@media (min-width: 768px) {
  .nav-rail {
    display: flex;
  }
  .bottom-bar {
    display: none;
  }
  .main-content {
    padding-bottom: 0;
  }
}
</style>
