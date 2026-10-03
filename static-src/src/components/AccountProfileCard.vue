<script setup lang="ts">
/**
 * My account: profile, languages, timezone and personal instructions (issue
 * #166). Renders the account store's state and forwards edits to it; all
 * validation, diffing and API calls live in `stores/account.ts` and
 * `services/account.ts`.
 */
import { computed, ref, watch } from 'vue';
import {
  RESPONSE_LANGUAGE_OPTIONS,
  accountMessageParams,
  draftFrom,
  fromResponseLanguageChoice,
  instructionsRemaining,
  showsChatPreferences,
  timezoneOptions,
  toResponseLanguageChoice,
  type AccountDraft,
  type ResponseLanguageChoice,
} from '@/services/account';
import { useAccountStore } from '@/stores/account';
import { useAuthStore } from '@/stores/auth';
import { useI18n, type MessageKey } from '@/i18n';
import type { UiLanguage } from '@/api/types';

const { t } = useI18n();
const account = useAccountStore();
const auth = useAuthStore();

const UI_LANGUAGES: readonly UiLanguage[] = ['de', 'fr', 'en'];

const draft = ref<AccountDraft | null>(null);
const errorKey = ref<MessageKey | null>(null);
const languageErrorKey = ref<MessageKey | null>(null);

// Seeded once the account loads; a later profile update (e.g. the timezone
// preset on another device) re-syncs it only after this card's own save.
watch(
  () => account.account,
  (value) => {
    if (value && draft.value === null) draft.value = draftFrom(value);
  },
  { immediate: true },
);

const showChatPrefs = computed(() => showsChatPreferences(auth.me));
const timezoneChoices = computed(() => timezoneOptions(draft.value?.timezone ?? null));
const responseChoice = computed<ResponseLanguageChoice>(() =>
  draft.value ? toResponseLanguageChoice(draft.value.response_language) : 'org_default',
);
const remaining = computed(() => instructionsRemaining(draft.value?.personal_instructions ?? ''));

function onResponseLanguageChange(event: Event): void {
  if (!draft.value) return;
  const choice = (event.target as HTMLSelectElement).value as ResponseLanguageChoice;
  draft.value.response_language = fromResponseLanguageChoice(choice);
}

async function setUiLanguage(lang: UiLanguage): Promise<void> {
  const result = await account.setUiLanguage(lang);
  languageErrorKey.value = result.ok ? null : result.messageKey;
}

async function handleSave(): Promise<void> {
  if (!draft.value) return;
  const result = await account.saveProfile(draft.value);
  if (result.ok) {
    errorKey.value = null;
    if (account.account) draft.value = draftFrom(account.account);
  } else {
    errorKey.value = result.messageKey;
  }
}
</script>

<template>
  <div v-if="account.loading && !draft" class="loading-wrap">
    <span class="s-loading-spinner" :aria-label="t('common.loading')" />
  </div>

  <template v-else>
    <p v-if="account.loadError" class="s-error">{{ t(account.loadError) }}</p>

    <template v-if="draft">
      <!-- Profile -->
      <div class="s-card">
        <div class="s-row">
          <div class="row-label">{{ t('account.profile.name.label') }}</div>
          <input v-model="draft.name" class="s-input" type="text" :disabled="account.saving" />
        </div>
        <div class="s-row">
          <div class="row-label">
            {{ t('account.profile.email.label') }}
            <span class="row-hint">{{ t('account.profile.email.hint') }}</span>
          </div>
          <input class="s-input" type="text" readonly :value="account.account?.email" />
        </div>
      </div>

      <!-- Languages -->
      <div class="section-head small-head">
        <h3 class="section-title small">{{ t('account.languages.title') }}</h3>
      </div>
      <div class="s-card">
        <div class="s-row">
          <div class="row-label">
            {{ t('account.languages.ui.label') }}
            <span class="row-hint">{{ t('account.languages.ui.hint') }}</span>
          </div>
          <div class="seg">
            <button
              v-for="lang in UI_LANGUAGES"
              :key="lang"
              type="button"
              class="seg-btn"
              :class="{ active: auth.me?.ui_language === lang }"
              @click="setUiLanguage(lang)"
            >
              {{ t(`account.language.${lang}` as MessageKey) }}
            </button>
          </div>
        </div>
        <div v-if="showChatPrefs" class="s-row">
          <div class="row-label">
            {{ t('account.languages.response.label') }}
            <span class="row-hint">{{ t('account.languages.response.hint') }}</span>
          </div>
          <select class="s-select" :value="responseChoice" @change="onResponseLanguageChange">
            <option v-for="choice in RESPONSE_LANGUAGE_OPTIONS" :key="choice" :value="choice">
              {{ choice === 'org_default' ? t('account.languages.response.orgDefault') : t(`account.language.${choice}` as MessageKey) }}
            </option>
          </select>
        </div>
        <div class="s-row">
          <div class="row-label">
            {{ t('account.timezone.label') }}
            <span class="row-hint">{{ t('account.timezone.hint') }}</span>
          </div>
          <select v-model="draft.timezone" class="s-select">
            <option v-for="zone in timezoneChoices" :key="zone" :value="zone">{{ zone }}</option>
          </select>
        </div>
      </div>
      <p v-if="languageErrorKey" class="s-error" role="alert">{{ t(languageErrorKey) }}</p>

      <!-- Personal instructions -->
      <div v-if="showChatPrefs" class="s-card">
        <div class="s-row stack">
          <div class="row-label">
            {{ t('account.instructions.label') }}
            <span class="row-hint">{{ t('account.instructions.hint') }}</span>
          </div>
          <textarea
            v-model="draft.personal_instructions"
            class="s-input account-instructions"
            :placeholder="t('account.instructions.placeholder')"
            :disabled="account.saving"
            rows="4"
          />
          <span class="row-hint">{{ t('account.instructions.remaining', { count: remaining }) }}</span>
        </div>
      </div>

      <p v-if="errorKey" class="s-error" role="alert">{{ t(errorKey, accountMessageParams(errorKey)) }}</p>

      <div class="account-save">
        <button class="s-btn primary" :disabled="account.saving" @click="handleSave">
          {{ t('account.profile.save') }}
        </button>
      </div>
    </template>
  </template>
</template>

<style scoped>
.loading-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  padding-top: 40px;
}

.section-head.small-head {
  margin-top: 4px;
}

.section-title.small {
  font-size: 15px;
}

.account-instructions {
  min-height: 96px;
  max-width: 100%;
  resize: vertical;
  font-family: inherit;
}

.account-save {
  display: flex;
  justify-content: flex-start;
}
</style>
