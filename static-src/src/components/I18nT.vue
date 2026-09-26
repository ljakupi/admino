<script setup lang="ts">
/**
 * I18nT (issue #144: PWA internationalization).
 *
 * Renders a catalog message that carries inline markup (e.g. `Run {cmd}
 * first`) without ever using `v-html`: `segments` splits the message into
 * text and `{slot}` segments BEFORE interpolating `params`, so a param value
 * (possibly user content, e.g. `'{cmd}'`) is always plain text and can never
 * turn into a slot. Text segments render as plain, Vue-escaped text; each
 * remaining named slot renders through the matching `<slot>` — so markup
 * around a placeholder (e.g. `<code>make start-local</code>`) is real
 * template content supplied by the caller, never a string parsed as HTML.
 * A slot with no matching provider falls back to the raw `{name}`
 * placeholder. `params.count` also selects the plural form.
 *
 * Usage, for a catalog entry `'settings.agent.startLocalHint': 'Run {cmd} first'`:
 *   <I18nT keypath="settings.agent.startLocalHint">
 *     <template #cmd><code>make start-local</code></template>
 *   </I18nT>
 */
import { computed } from 'vue';
import { segments as resolveSegments, type MessageKey, type Params } from '@/i18n';

const props = defineProps<{
  keypath: MessageKey;
  params?: Params;
  tag?: string;
}>();

const segments = computed(() => resolveSegments(props.keypath, props.params));

/** The raw `{name}` text shown when the caller provides no slot for `name`. */
function placeholder(name: string): string {
  return `{${name}}`;
}
</script>

<template>
  <component :is="tag ?? 'span'">
    <template v-for="(segment, index) in segments" :key="index">
      <template v-if="segment.kind === 'text'">{{ segment.text }}</template>
      <slot v-else :name="segment.name">{{ placeholder(segment.name) }}</slot>
    </template>
  </component>
</template>
