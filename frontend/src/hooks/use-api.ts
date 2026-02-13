"use client";

import useSWR from "swr";
import { useAuth } from "@clerk/nextjs";
import { api, type Scan, type Target, type ScanStats, type APIKey } from "@/lib/api";

// Token cache to avoid repeated getToken calls
let cachedToken: string | null = null;
let tokenCacheTime = 0;
const TOKEN_CACHE_MS = 30000; // 30 seconds

// Custom hook that provides token-aware fetching with SWR caching
function useAuthenticatedSWR<T>(key: string | null, fetcher: (token: string) => Promise<T>, options?: { refreshInterval?: number }) {
  const { getToken } = useAuth();

  return useSWR<T>(
    key,
    async () => {
      // Use cached token if available and fresh
      const now = Date.now();
      if (cachedToken && (now - tokenCacheTime) < TOKEN_CACHE_MS) {
        return fetcher(cachedToken);
      }

      const token = await getToken();
      if (!token) throw new Error("Not authenticated");

      // Cache the token
      cachedToken = token;
      tokenCacheTime = now;

      return fetcher(token);
    },
    {
      revalidateOnFocus: false, // Don't refetch when window regains focus
      revalidateOnReconnect: false, // Don't refetch on reconnect
      dedupingInterval: 10000, // Dedupe requests within 10 seconds
      errorRetryCount: 2,
      keepPreviousData: true, // Show stale data while revalidating
      ...options,
    }
  );
}

// Targets
export function useTargets() {
  return useAuthenticatedSWR<Target[]>("targets", (token) => api.listTargets(token));
}

// Scans
export function useScans(page = 1) {
  return useAuthenticatedSWR<{ items: Scan[]; total: number }>(
    `scans-${page}`,
    (token) => api.listScans(token, page)
  );
}

export function useScan(id: string | null) {
  return useAuthenticatedSWR(
    id ? `scan-${id}` : null,
    (token) => api.getScan(token, id!)
  );
}

// Stats
export function useStats() {
  return useAuthenticatedSWR<ScanStats>("stats", (token) => api.getStats(token));
}

// API Keys
export function useAPIKeys() {
  return useAuthenticatedSWR<APIKey[]>("api-keys", (token) => api.listAPIKeys(token));
}
