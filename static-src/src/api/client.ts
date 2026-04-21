const TIMEOUT_MS = 30_000;

export class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    message?: string,
  ) {
    super(message ?? `${status} ${statusText}`);
    this.name = 'ApiError';
  }
}

function getAuthHeader(): Record<string, string> {
  const token = localStorage.getItem('admino_auth_token');
  if (token) {
    return { Authorization: `Bearer ${token}` };
  }
  return {};
}

export async function fetchJson<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(path, {
      ...init,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeader(),
        ...(init.headers as Record<string, string> | undefined),
      },
    });

    if (!res.ok) {
      throw new ApiError(res.status, res.statusText);
    }

    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}
