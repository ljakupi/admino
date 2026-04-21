import { useSettingsStore } from '@/stores/settings';

const TOKEN_RE = /^[\x21-\x7E]{8,512}$/;

export function useAuth() {
  const settings = useSettingsStore();

  function isValidToken(value: string): boolean {
    return TOKEN_RE.test(value);
  }

  return {
    token: settings.token,
    needsAuth: settings.needsAuth,
    setToken: settings.setToken,
    skipAuth: settings.skipAuth,
    isValidToken,
  };
}
