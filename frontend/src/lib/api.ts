import { getSession } from "next-auth/react";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// Attach the VEXIS JWT (obtained from the GitHub token at sign-in) so backend
// requests are authenticated and scoped to the signed-in user.
export async function authHeaders(): Promise<Record<string, string>> {
  try {
    const session = await getSession();
    const token = (session as any)?.vexisToken;
    return token ? { Authorization: `Bearer ${token}` } : {};
  } catch {
    return {};
  }
}

async function jsonHeaders(): Promise<Record<string, string>> {
  return { "Content-Type": "application/json", ...(await authHeaders()) };
}

export const api = {
  async startScan(payload: { source_type: string; source: string; language?: string }) {
    const resp = await fetch(`${BASE}/api/v1/scan`, {
      method: "POST",
      headers: await jsonHeaders(),
      body: JSON.stringify(payload),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },

  async getScan(id: string) {
    const resp = await fetch(`${BASE}/api/v1/scan/${id}`, { headers: await authHeaders() });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },

  async getFindings(scanId: string) {
    const resp = await fetch(`${BASE}/api/v1/scan/${scanId}/findings`, { headers: await authHeaders() });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },

  async getFinding(id: string) {
    const resp = await fetch(`${BASE}/api/v1/finding/${id}`, { headers: await authHeaders() });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },

  async triageFinding(id: string, status: string, notes?: string) {
    const resp = await fetch(`${BASE}/api/v1/finding/${id}/triage`, {
      method: "POST",
      headers: await jsonHeaders(),
      body: JSON.stringify({ status, notes }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },

  // Autofix + PR generation
  async generateAutofix(findingId: string) {
    const resp = await fetch(`${BASE}/api/v1/finding/${findingId}/autofix/generate`, {
      method: "POST",
      headers: await jsonHeaders(),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },

  async openPullRequest(findingId: string, repoUrl?: string) {
    const resp = await fetch(`${BASE}/api/v1/finding/${findingId}/pr`, {
      method: "POST",
      headers: await jsonHeaders(),
      body: JSON.stringify({ repo_url: repoUrl ?? null }),
    });
    if (!resp.ok) {
      const detail = await resp.json().catch(() => ({}));
      throw new Error(detail.detail ?? `HTTP ${resp.status}`);
    }
    return resp.json();
  },
};
