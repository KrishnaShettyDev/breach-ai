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
    const errorData = await response.json().catch(() => ({ detail: "Request failed" }));
    // Handle various error response formats
    let message = "Request failed";
    if (typeof errorData.detail === "string") {
      message = errorData.detail;
    } else if (Array.isArray(errorData.detail)) {
      // Pydantic validation errors
      message = errorData.detail.map((e: { msg: string }) => e.msg).join(", ");
    } else if (errorData.error) {
      message = errorData.error;
    } else if (errorData.message) {
      message = errorData.message;
    }
    throw new Error(message);
  }

  return response.json();
}

// Types
export interface Scan {
  id: string;
  organization_id: string;
  target_id?: string | null;
  target_url: string;
  mode: string;
  status: string;
  progress: number;
  current_phase?: string | null;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  total_business_impact: number;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  error_message?: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id?: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  endpoint: string;
  method: string;
  parameter?: string | null;
  business_impact: number | null;
  impact_explanation?: string | null;
  records_exposed?: number;
  pii_fields?: string[];
  fix_suggestion: string | null;
  references?: string[];
  curl_command: string | null;
  is_false_positive?: boolean;
  is_resolved?: boolean;
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
  scans_this_month: number;
  running_scans: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  total_business_impact: number;
  avg_scan_duration: number | null;
}

export interface APIKey {
  id: string;
  name: string;
  key_prefix: string;
  scopes: string[];
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
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

  async createScan(token: string, data: { target_id?: string; target_url: string; mode: string }): Promise<Scan> {
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

  // API Keys
  async listAPIKeys(token: string): Promise<APIKey[]> {
    return fetchAPI("/api/v1/auth/api-keys", { token });
  },

  async createAPIKey(token: string, data: { name: string; scopes?: string[]; expires_in_days?: number }): Promise<{ api_key: APIKey; raw_key: string }> {
    return fetchAPI("/api/v1/auth/api-keys", {
      method: "POST",
      token,
      body: JSON.stringify(data),
    });
  },

  async deleteAPIKey(token: string, id: string): Promise<void> {
    await fetchAPI(`/api/v1/auth/api-keys/${id}`, { method: "DELETE", token });
  },
};
