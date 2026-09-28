<script setup lang="ts">
defineProps<{
  title: string;
}>();
</script>

<template>
  <div class="auth-page">
    <div class="auth-card">
      <div class="auth-brand">admino</div>
      <h1 class="auth-title">{{ title }}</h1>
      <slot />
    </div>
  </div>
</template>

<style scoped>
.auth-page {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow-y: auto;
  padding: var(--space-6) var(--space-4);
  background: var(--color-bg);
}

.auth-card {
  width: 100%;
  max-width: 380px;
  background: var(--color-bg-elevated);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-card);
  box-shadow: var(--shadow-card);
  padding: var(--space-8) var(--space-6);
}

.auth-brand {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 22px;
  color: var(--color-primary);
  letter-spacing: -0.02em;
  margin-bottom: var(--space-2);
}

.auth-title {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: var(--fs-h2);
  color: var(--color-text);
  margin-bottom: var(--space-6);
}
</style>
