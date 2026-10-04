<script setup lang="ts">
/**
 * Organization -> Settings tab (issue #169): profile, instructions, security,
 * data and plan, tools and a web-access placeholder. Binds the org settings
 * store's draft and forwards Save/Reset; validation, diffing and API calls
 * live in `stores/orgSettings.ts` and `services/orgSettings.ts`.
 *
 * Security notes: nothing is logged; the instructions are bound to a
 * textarea and shown as text only (no `v-html`); residency and plan are
 * read-only; server error text is never shown (catalog messages only).
 */
import { computed, onMounted } from 'vue';
import OrgServicesCard from '@/components/OrgServicesCard.vue';
import BaseButton from '@/components/BaseButton.vue';
import { useOrgSettingsStore } from '@/stores/orgSettings';
import {
  RESPONSE_LANGUAGES,
  orgSettingsIssueText,
  planStorageLabel,
  type OrgSettingsIssue,
} from '@/services/orgSettings';
import { canManageOrgSettings } from '@/services/access';
import { useAuthStore } from '@/stores/auth';
import { useI18n, type MessageKey } from '@/i18n';

const emit = defineEmits<{ 'open-permissions': [] }>();

const { t } = useI18n();
const store = useOrgSettingsStore();
const auth = useAuthStore();

onMounted(() => store.load());

const bounds = computed(() => ({
  min: store.settings?.retention.trash_min_days ?? 0,
  max: store.settings?.retention.trash_max_days ?? 0,
}));

function errorFor(...fields: OrgSettingsIssue[]): string | undefined {
  const found = store.issues.find((i) => fields.includes(i));
  return found ? orgSettingsIssueText(found, store.settings) : undefined;
}
</script>

<template>
  <template v-if="canManageOrgSettings(auth.role)">
    <div v-if="store.loading && !store.draft" class="loading-wrap">
      <span class="s-loading-spinner" :aria-label="t('common.loading')" />
    </div>

    <template v-else>
      <p v-if="store.loadError" class="s-error" role="alert">{{ store.loadError }}</p>

      <template v-if="store.draft">
        <h2 class="section-title">{{ t('organization.settings.title') }}</h2>

        <!-- Profile -->
        <section class="settings-section">
          <h3 class="section-title small">{{ t('organization.settings.profile.title') }}</h3>
          <div class="s-card pad">
            <label class="field">
              <span class="row-label">{{ t('organization.settings.profile.displayName') }}</span>
              <input
                v-model="store.draft.display_name"
                class="s-input"
                type="text"
                :disabled="store.saving"
              />
              <span v-if="errorFor('name_required', 'name_too_long')" class="s-error" role="alert">
                {{ errorFor('name_required', 'name_too_long') }}
              </span>
            </label>
            <label class="field">
              <span class="row-label">{{ t('organization.settings.profile.responseLanguage') }}</span>
              <select
                v-model="store.draft.default_response_language"
                class="s-select"
                :disabled="store.saving"
              >
                <option v-for="lang in RESPONSE_LANGUAGES" :key="lang" :value="lang">
                  {{ t(`account.language.${lang}` as MessageKey) }}
                </option>
              </select>
            </label>
          </div>
        </section>

        <!-- Instructions -->
        <section class="settings-section">
          <h3 class="section-title small">{{ t('organization.settings.instructions.title') }}</h3>
          <div class="s-card pad">
            <label class="field">
              <span class="row-hint">{{ t('organization.settings.instructions.hint') }}</span>
              <textarea
                v-model="store.draft.instructions"
                class="s-input instructions"
                rows="6"
                :disabled="store.saving"
              />
            </label>
            <span class="row-hint">
              {{ t('organization.settings.instructions.remaining', { count: store.instructionsRemaining }) }}
            </span>
            <span v-if="errorFor('instructions_too_long')" class="s-error" role="alert">
              {{ errorFor('instructions_too_long') }}
            </span>
          </div>
        </section>

        <!-- Security -->
        <section class="settings-section">
          <h3 class="section-title small">{{ t('organization.settings.security.title') }}</h3>
          <div class="s-card pad">
            <label class="field">
              <span class="row-label">{{ t('organization.settings.security.idleTimeout') }}</span>
              <input
                v-model.number="store.draft.session_idle_timeout_minutes"
                class="s-input"
                type="number"
                inputmode="numeric"
                :disabled="store.saving"
              />
              <span v-if="errorFor('idle_timeout_range')" class="s-error" role="alert">
                {{ errorFor('idle_timeout_range') }}
              </span>
            </label>
            <label class="field">
              <span class="row-label">{{ t('organization.settings.security.lifetime') }}</span>
              <input
                v-model.number="store.draft.session_max_lifetime_hours"
                class="s-input"
                type="number"
                inputmode="numeric"
                :disabled="store.saving"
              />
              <span v-if="errorFor('lifetime_range')" class="s-error" role="alert">
                {{ errorFor('lifetime_range') }}
              </span>
            </label>
            <span class="row-hint">{{ t('organization.settings.security.hint') }}</span>
          </div>
        </section>

        <!-- Data and plan -->
        <section class="settings-section">
          <h3 class="section-title small">{{ t('organization.settings.data.title') }}</h3>
          <div class="s-card pad">
            <label class="field">
              <span class="row-label">{{ t('organization.settings.data.trashRetention') }}</span>
              <input
                v-model.number="store.draft.trash_retention_days"
                class="s-input"
                type="number"
                inputmode="numeric"
                :disabled="store.saving"
              />
              <span class="row-hint">{{ t('organization.settings.data.trashBounds', bounds) }}</span>
              <span v-if="errorFor('trash_retention_range')" class="s-error" role="alert">
                {{ errorFor('trash_retention_range') }}
              </span>
            </label>
            <div class="field">
              <span class="row-label">{{ t('organization.settings.data.residency') }}</span>
              <span>
                {{
                  store.dataResidency
                    ? t('organization.settings.data.residencyOn')
                    : t('organization.settings.data.residencyOff')
                }}
              </span>
              <span class="row-hint">{{ t('organization.settings.data.residencyHint') }}</span>
            </div>
            <div v-if="store.settings" class="field">
              <span>{{ t('organization.settings.data.seats', { count: store.settings.plan.seats }) }}</span>
              <span>{{ planStorageLabel(store.settings.plan.storage_quota) }}</span>
            </div>
          </div>
        </section>

        <!-- Tools and permissions -->
        <section class="settings-section">
          <h3 class="section-title small">{{ t('organization.settings.tools.title') }}</h3>
          <OrgServicesCard />
          <div class="s-card pad">
            <div class="field placeholder-row" aria-disabled="true">
              {{ t('organization.settings.tools.mailboxesPlaceholder') }}
            </div>
            <div>
              <BaseButton variant="secondary" @click="emit('open-permissions')">
                {{ t('organization.settings.tools.permissionsLink') }}
              </BaseButton>
            </div>
          </div>
        </section>

        <!-- Web access (placeholder, #248) -->
        <section class="settings-section">
          <h3 class="section-title small">{{ t('organization.settings.webAccess.title') }}</h3>
          <div class="s-card pad">
            <p class="row-hint">{{ t('organization.settings.webAccess.placeholder') }}</p>
          </div>
        </section>

        <p v-if="store.saveError" class="s-error" role="alert">{{ store.saveError }}</p>

        <div class="actions">
          <BaseButton :disabled="store.saving || !store.dirty" :loading="store.saving" @click="store.save()">
            {{ t('organization.settings.save') }}
          </BaseButton>
          <BaseButton variant="ghost" :disabled="store.saving || !store.dirty" @click="store.resetDraft()">
            {{ t('organization.settings.reset') }}
          </BaseButton>
        </div>
      </template>
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

.section-title {
  font-family: var(--font-display);
  font-weight: var(--fw-bold);
  font-size: 18px;
  letter-spacing: -0.015em;
  color: var(--color-text);
}

.section-title.small {
  font-size: 15px;
}

.settings-section {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.s-card.pad {
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 16px 20px;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.instructions {
  min-height: 120px;
  max-width: 100%;
  resize: vertical;
  font-family: inherit;
}

.placeholder-row {
  min-height: 44px;
  justify-content: center;
  opacity: 0.5;
  font-size: 14px;
}

.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}
</style>
