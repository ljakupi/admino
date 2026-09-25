<script setup lang="ts">
import { computed } from 'vue';
import { marked } from 'marked';
import DOMPurify from 'dompurify';

const props = defineProps<{
  content: string;
}>();

const rendered = computed(() => {
  const raw = marked.parse(props.content, { async: false }) as string;
  return DOMPurify.sanitize(raw, {
    ALLOWED_TAGS: [
      'p', 'br', 'strong', 'em', 'code', 'pre', 'ul', 'ol', 'li',
      'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'blockquote',
      'table', 'thead', 'tbody', 'tr', 'th', 'td', 'hr', 'span',
    ],
    // No `target`: an LLM-authored link opening a new tab could reach
    // window.opener (reverse tabnabbing). No `data-*`: unneeded attack surface.
    ALLOWED_ATTR: ['href', 'rel', 'class'],
    ALLOW_DATA_ATTR: false,
  });
});
</script>

<template>
  <!-- eslint-disable vue/no-v-html -->
  <div class="markdown-block" v-html="rendered" />
</template>

<style scoped>
.markdown-block {
  line-height: var(--lh-relaxed);
  word-break: break-word;
}

.markdown-block :deep(p) {
  margin-bottom: var(--space-2);
}
.markdown-block :deep(p:last-child) {
  margin-bottom: 0;
}

.markdown-block :deep(code) {
  font-family: var(--font-mono);
  font-size: var(--fs-mono);
  background: var(--color-bg);
  padding: 1px var(--space-1);
  border-radius: 4px;
}

.markdown-block :deep(pre) {
  background: var(--color-text);
  color: var(--color-bg-surface);
  padding: var(--space-3);
  border-radius: var(--radius-input);
  overflow-x: auto;
  margin: var(--space-2) 0;
}

.markdown-block :deep(pre code) {
  background: none;
  padding: 0;
  color: inherit;
}

.markdown-block :deep(ul),
.markdown-block :deep(ol) {
  padding-left: var(--space-5);
  margin: var(--space-2) 0;
}

.markdown-block :deep(ul) {
  list-style: disc;
}

.markdown-block :deep(ol) {
  list-style: decimal;
}

.markdown-block :deep(li) {
  margin-bottom: var(--space-1);
}

.markdown-block :deep(table) {
  width: 100%;
  border-collapse: collapse;
  margin: var(--space-2) 0;
  font-size: var(--fs-caption);
}

.markdown-block :deep(th),
.markdown-block :deep(td) {
  padding: var(--space-2) var(--space-3);
  border: 1px solid var(--color-border);
  text-align: left;
}

.markdown-block :deep(th) {
  background: var(--color-bg);
  font-weight: var(--fw-semibold);
}

.markdown-block :deep(blockquote) {
  border-left: 3px solid var(--color-primary-mid);
  padding-left: var(--space-3);
  color: var(--color-text-muted);
  margin: var(--space-2) 0;
}

.markdown-block :deep(a) {
  color: var(--color-primary-mid);
  text-decoration: underline;
}

.markdown-block :deep(hr) {
  border: none;
  border-top: 1px solid var(--color-border);
  margin: var(--space-4) 0;
}
</style>
