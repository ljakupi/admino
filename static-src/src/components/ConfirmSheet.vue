<script setup lang="ts">
import BaseButton from './BaseButton.vue';

defineProps<{
  heading: string;
  subtext?: string;
  confirmLabel?: string;
  variant?: 'neutral' | 'destructive';
}>();

defineEmits<{
  confirm: [];
  cancel: [];
}>();
</script>

<template>
  <Teleport to="body">
    <div class="sheet-backdrop" @click.self="$emit('cancel')">
      <div class="sheet" role="dialog" aria-modal="true">
        <div class="sheet-handle" />
        <h3 class="sheet-heading">{{ heading }}</h3>
        <p v-if="subtext" class="sheet-subtext caption">{{ subtext }}</p>
        <div class="sheet-actions">
          <BaseButton variant="secondary" @click="$emit('cancel')">Cancel</BaseButton>
          <BaseButton
            :variant="variant === 'destructive' ? 'destructive' : 'primary'"
            @click="$emit('confirm')"
          >
            {{ confirmLabel ?? 'Confirm' }}
          </BaseButton>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.sheet-backdrop {
  position: fixed;
  inset: 0;
  background: var(--color-overlay);
  display: flex;
  align-items: flex-end;
  justify-content: center;
  z-index: 500;
  animation: fade-in var(--dur-med) var(--ease);
}

@media (min-width: 768px) {
  .sheet-backdrop {
    align-items: center;
  }
}

.sheet {
  background: var(--color-bg-elevated);
  padding: var(--space-6);
  width: 90%;
  max-width: 400px;
  border-radius: var(--radius-pill) var(--radius-pill) 0 0;
  animation: slide-up var(--dur-med) var(--ease);
}

@media (min-width: 768px) {
  .sheet {
    border-radius: var(--radius-card);
    box-shadow: var(--shadow-modal);
  }
}

.sheet-handle {
  width: 36px;
  height: 4px;
  background: var(--color-border-strong);
  border-radius: 2px;
  margin: 0 auto var(--space-5);
}

@media (min-width: 768px) {
  .sheet-handle { display: none; }
}

.sheet-heading {
  margin-bottom: var(--space-2);
}

.sheet-subtext {
  margin-bottom: var(--space-5);
}

.sheet-actions {
  display: flex;
  gap: var(--space-3);
  justify-content: flex-end;
}

@keyframes fade-in {
  from { opacity: 0; }
  to { opacity: 1; }
}

@keyframes slide-up {
  from { transform: translateY(100%); }
  to { transform: translateY(0); }
}

@media (min-width: 768px) {
  @keyframes slide-up {
    from { transform: scale(0.95); opacity: 0; }
    to { transform: scale(1); opacity: 1; }
  }
}
</style>
