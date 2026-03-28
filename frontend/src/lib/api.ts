const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export const api = {
  async startScan(payload: { source_type: string; source: string; language?: string }) {
    const resp = await fetch(`${BASE}/api/v1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },

  async getScan(id: string) {
    const resp = await fetch(`${BASE}/api/v1/scan/${id}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },

  async getFindings(scanId: string) {
    const resp = await fetch(`${BASE}/api/v1/scan/${scanId}/findings`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },

  async getFinding(id: string) {
    const resp = await fetch(`${BASE}/api/v1/finding/${id}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },

  async triageFinding(id: string, status: string, notes?: string) {
    const resp = await fetch(`${BASE}/api/v1/finding/${id}/triage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, notes }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  },
};
