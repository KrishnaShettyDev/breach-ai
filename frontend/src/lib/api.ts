const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface FetchOptions extends RequestInit {
  token?: string;
}

async function fetchAPI<T>(
  endpoint: string,
  options: FetchOptions = {}
): Promise<T> {
  const { token, ...fetchOptions } = options;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_URL}${endpoint}`, {
    ...fetchOptions,
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: "Request failed" }));
    throw new Error(error.error || error.detail || "Request failed");
  }

  return response.json();
}

// Types
export interface Scan {
  id: string;
  target_url: string;
  mode: string;
  status: string;
  progress: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  created_at: string;
}

export interface Finding {
  id: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  endpoint: string;
  method: string;
  business_impact: number | null;
  fix_suggestion: string;
  curl_command: string;
  discovered_at: string;
}

export interface Target {
  id: string;
  url: string;
  name: string;
  description: string;
  is_verified: boolean;
  verification_token: string;
  created_at: string;
}

export interface ScanStats {
  total_scans: number;
  running_scans: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
}

// API Functions
export const api = {
  // Scans
  async listScans(token: string, page = 1): Promise<{ items: Scan[]; total: number }> {
    return fetchAPI(`/api/v1/scans?page=${page}`, { token });
  },

  async getScan(token: string, id: string): Promise<Scan & { findings: Finding[] }> {
    return fetchAPI(`/api/v1/scans/${id}`, { token });
  },

  async createScan(token: string, data: { target_id?: string; target_url?: string; mode: string }): Promise<Scan> {
    return fetchAPI("/api/v1/scans", {
      method: "POST",
      token,
      body: JSON.stringify(data),
    });
  },

  async cancelScan(token: string, id: string): Promise<Scan> {
    return fetchAPI(`/api/v1/scans/${id}/cancel`, { method: "POST", token });
  },

  async getStats(token: string): Promise<ScanStats> {
    return fetchAPI("/api/v1/scans/stats", { token });
  },

  // Targets
  async listTargets(token: string): Promise<Target[]> {
    return fetchAPI("/api/v1/targets", { token });
  },

  async createTarget(token: string, data: { url: string; name: string; description?: string }): Promise<Target> {
    return fetchAPI("/api/v1/targets", {
      method: "POST",
      token,
      body: JSON.stringify(data),
    });
  },

  async deleteTarget(token: string, id: string): Promise<void> {
    await fetchAPI(`/api/v1/targets/${id}`, { method: "DELETE", token });
  },

  async verifyTarget(token: string, id: string, method: string): Promise<{ success: boolean; message: string }> {
    return fetchAPI(`/api/v1/targets/${id}/verify?method=${method}`, { method: "POST", token });
  },

  // Auth
  async getMe(token: string): Promise<{ id: string; email: string; name: string }> {
    return fetchAPI("/api/v1/auth/me", { token });
  },
};
