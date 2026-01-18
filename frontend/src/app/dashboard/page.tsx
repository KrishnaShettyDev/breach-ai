"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { api, type Scan, type ScanStats } from "@/lib/api";
import { formatDate, formatDuration } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Plus, ArrowRight } from "lucide-react";

export default function DashboardPage() {
  const { getToken } = useAuth();
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const token = await getToken();
        if (!token) return;

        const [statsData, scansData] = await Promise.all([
          api.getStats(token),
          api.listScans(token, 1),
        ]);

        setStats(statsData);
        setRecentScans(scansData.items.slice(0, 5));
      } catch (error) {
        console.error("Failed to load dashboard data:", error);
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [getToken]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#737373]">Loading...</div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Dashboard</h1>
          <p className="text-[#737373] mt-1">Overview of your security posture</p>
        </div>
        <Link href="/dashboard/scans/new">
          <Button>
            <Plus className="w-4 h-4 mr-2" />
            New Scan
          </Button>
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-3xl font-semibold">{stats?.total_scans || 0}</div>
            <div className="text-sm text-[#737373] mt-1">Total Scans</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-3xl font-semibold">{stats?.running_scans || 0}</div>
            <div className="text-sm text-[#737373] mt-1">Running</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-3xl font-semibold text-red-600">{stats?.critical_findings || 0}</div>
            <div className="text-sm text-[#737373] mt-1">Critical Findings</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="text-3xl font-semibold">{stats?.total_findings || 0}</div>
            <div className="text-sm text-[#737373] mt-1">Total Findings</div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Scans */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Recent Scans</CardTitle>
          <Link href="/dashboard/scans" className="text-sm text-[#737373] hover:text-black flex items-center gap-1">
            View all <ArrowRight className="w-3 h-3" />
          </Link>
        </CardHeader>
        <CardContent>
          {recentScans.length === 0 ? (
            <div className="text-center py-8 text-[#737373]">
              <p>No scans yet</p>
              <Link href="/dashboard/scans/new">
                <Button variant="outline" className="mt-4">
                  Run your first scan
                </Button>
              </Link>
            </div>
          ) : (
            <div className="space-y-3">
              {recentScans.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/dashboard/scans/${scan.id}`}
                  className="flex items-center justify-between p-4 border border-[#e5e5e5] rounded-lg hover:bg-[#f5f5f5] transition-colors"
                >
                  <div className="flex-1 min-w-0">
                    <div className="font-medium truncate">{scan.target_url}</div>
                    <div className="text-sm text-[#737373] mt-1">
                      {formatDate(scan.started_at)} · {formatDuration(scan.duration_seconds)}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 ml-4">
                    {scan.critical_count > 0 && (
                      <Badge variant="severity" severity="critical">
                        {scan.critical_count} Critical
                      </Badge>
                    )}
                    {scan.high_count > 0 && (
                      <Badge variant="severity" severity="high">
                        {scan.high_count} High
                      </Badge>
                    )}
                    <Badge>{scan.status}</Badge>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
