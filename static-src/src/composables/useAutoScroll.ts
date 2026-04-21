import { ref, nextTick, type Ref } from 'vue';

const THRESHOLD = 80;

export function useAutoScroll(containerRef: Ref<HTMLElement | null>) {
  const isNearBottom = ref(true);

  function onScroll() {
    const el = containerRef.value;
    if (!el) return;
    isNearBottom.value =
      el.scrollHeight - el.scrollTop - el.clientHeight < THRESHOLD;
  }

  async function scrollToBottom(force = false) {
    if (!force && !isNearBottom.value) return;
    await nextTick();
    const el = containerRef.value;
    if (el) {
      el.scrollTop = el.scrollHeight;
    }
  }

  return { isNearBottom, onScroll, scrollToBottom };
}
