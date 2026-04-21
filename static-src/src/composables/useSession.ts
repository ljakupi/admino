import { useSettingsStore } from '@/stores/settings';

export function useSession() {
  const settings = useSettingsStore();

  return {
    sessionId: settings.sessionId,
    newSession: settings.newSession,
  };
}
