"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api, type Scan } from "@/lib/api";
import { formatDate, formatDuration } from "@/lib/utils";
import { Plus, ExternalLink } from "lucide-react";

export default function ScansPage() {
  const { getToken } = useAuth();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    async function loadScans() {
      try {
        const token = await getToken();
        if (!token) return;

        const data = await api.listScans(token, page);
        setScans(data.items);
        setTotal(data.total);
      } catch (error) {
        console.error("Failed to load scans:", error);
      } finally {
        setLoading(false);
      }
    }

    loadScans();
  }, [getToken, page]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#737373]">Loading...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Scans</h1>
          <p className="text-[#737373] mt-1">{total} total scans</p>
        </div>
        <Link href="/dashboard/scans/new">
          <Button>
            <Plus className="w-4 h-4 mr-2" />
            New Scan
          </Button>
        </Link>
      </div>

      {/* Scans List */}
      {scans.length === 0 ? (
        <Card className="p-12 text-center">
          <p className="text-[#737373] mb-4">No scans yet</p>
          <Link href="/dashboard/scans/new">
            <Button>Run your first scan</Button>
          </Link>
        </Card>
      ) : (
        <div className="space-y-3">
          {scans.map((scan) => (
            <Link key={scan.id} href={`/dashboard/scans/${scan.id}`}>
              <Card className="p-4 hover:bg-[#f5f5f5] transition-colors cursor-pointer">
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium truncate">{scan.target_url}</span>
                      <ExternalLink className="w-3 h-3 text-[#a3a3a3]" />
                    </div>
                    <div className="flex items-center gap-4 text-sm text-[#737373] mt-2">
                      <span>{formatDate(scan.started_at)}</span>
                      <span>{formatDuration(scan.duration_seconds)}</span>
                      <span className="uppercase text-xs">{scan.mode}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 ml-4">
                    <div className="text-right">
                      <div className="text-sm font-medium">{scan.findings_count} findings</div>
                      <div className="flex items-center gap-2 mt-1">
                        {scan.critical_count > 0 && (
                          <span className="text-xs severity-critical">{scan.critical_count}C</span>
                        )}
                        {scan.high_count > 0 && (
                          <span className="text-xs severity-high">{scan.high_count}H</span>
                        )}
                        {scan.medium_count > 0 && (
                          <span className="text-xs severity-medium">{scan.medium_count}M</span>
                        )}
                        {scan.low_count > 0 && (
                          <span className="text-xs severity-low">{scan.low_count}L</span>
                        )}
                      </div>
                    </div>
                    <Badge
                      className={
                        scan.status === "completed"
                          ? "bg-green-100 text-green-700"
                          : scan.status === "running"
                          ? "bg-blue-100 text-blue-700"
                          : scan.status === "failed"
                          ? "bg-red-100 text-red-700"
                          : ""
                      }
                    >
                      {scan.status}
                    </Badge>
                  </div>
                </div>
                {scan.status === "running" && (
                  <div className="mt-3">
                    <div className="w-full bg-[#e5e5e5] rounded-full h-1.5">
                      <div
                        className="bg-black h-1.5 rounded-full transition-all"
                        style={{ width: `${scan.progress}%` }}
                      />
                    </div>
                  </div>
                )}
              </Card>
            </Link>
          ))}
        </div>
      )}

      {/* Pagination */}
      {total > 20 && (
        <div className="flex items-center justify-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page === 1}
            onClick={() => setPage(page - 1)}
          >
            Previous
          </Button>
          <span className="text-sm text-[#737373]">Page {page}</span>
          <Button
            variant="outline"
            size="sm"
            disabled={scans.length < 20}
            onClick={() => setPage(page + 1)}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
}
