"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api, type Scan, type Finding } from "@/lib/api";
import { formatDate, formatDuration, cn } from "@/lib/utils";
import { ArrowLeft, Download, ExternalLink, ChevronDown, ChevronUp } from "lucide-react";

export default function ScanDetailPage() {
  const { getToken } = useAuth();
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<(Scan & { findings: Finding[] }) | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

  useEffect(() => {
    async function loadScan() {
      try {
        const token = await getToken();
        if (!token) return;

        const data = await api.getScan(token, scanId);
        setScan(data);
      } catch (error) {
        console.error("Failed to load scan:", error);
      } finally {
        setLoading(false);
      }
    }

    loadScan();

    // Poll for updates if scan is running
    const interval = setInterval(async () => {
      if (scan?.status === "running") {
        try {
          const token = await getToken();
          if (!token) return;
          const data = await api.getScan(token, scanId);
          setScan(data);
        } catch {}
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [getToken, scanId, scan?.status]);

  const toggleFinding = (id: string) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#737373]">Loading...</div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <p className="text-[#737373]">Scan not found</p>
        <Link href="/dashboard/scans">
          <Button variant="outline" className="mt-4">
            Back to Scans
          </Button>
        </Link>
      </div>
    );
  }

  const sortedFindings = [...(scan.findings || [])].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (severityOrder[a.severity as keyof typeof severityOrder] || 5) -
           (severityOrder[b.severity as keyof typeof severityOrder] || 5);
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <Link
            href="/dashboard/scans"
            className="text-sm text-[#737373] hover:text-black flex items-center gap-1 mb-2"
          >
            <ArrowLeft className="w-3 h-3" />
            Back to Scans
          </Link>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            {scan.target_url}
            <ExternalLink className="w-4 h-4 text-[#a3a3a3]" />
          </h1>
          <div className="flex items-center gap-4 text-sm text-[#737373] mt-2">
            <span>{formatDate(scan.started_at)}</span>
            <span>{formatDuration(scan.duration_seconds)}</span>
            <span className="uppercase">{scan.mode} scan</span>
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
        <a
          href={`${process.env.NEXT_PUBLIC_API_URL}/api/v1/scans/${scan.id}/export?format=html`}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center h-10 px-4 rounded-lg text-sm font-medium border border-black bg-white text-black hover:bg-[#f5f5f5] transition-colors"
        >
          <Download className="w-4 h-4 mr-2" />
          Export Report
        </a>
      </div>

      {/* Progress */}
      {scan.status === "running" && (
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium">Scan in progress</span>
              <span className="text-sm text-[#737373]">{scan.progress}%</span>
            </div>
            <div className="w-full bg-[#e5e5e5] rounded-full h-2">
              <div
                className="bg-black h-2 rounded-full transition-all"
                style={{ width: `${scan.progress}%` }}
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="pt-6 text-center">
            <div className="text-2xl font-semibold">{scan.findings_count}</div>
            <div className="text-xs text-[#737373] mt-1">Total</div>
          </CardContent>
        </Card>
        <Card className="bg-severity-critical">
          <CardContent className="pt-6 text-center">
            <div className="text-2xl font-semibold severity-critical">{scan.critical_count}</div>
            <div className="text-xs text-[#737373] mt-1">Critical</div>
          </CardContent>
        </Card>
        <Card className="bg-severity-high">
          <CardContent className="pt-6 text-center">
            <div className="text-2xl font-semibold severity-high">{scan.high_count}</div>
            <div className="text-xs text-[#737373] mt-1">High</div>
          </CardContent>
        </Card>
        <Card className="bg-severity-medium">
          <CardContent className="pt-6 text-center">
            <div className="text-2xl font-semibold severity-medium">{scan.medium_count}</div>
            <div className="text-xs text-[#737373] mt-1">Medium</div>
          </CardContent>
        </Card>
        <Card className="bg-severity-low">
          <CardContent className="pt-6 text-center">
            <div className="text-2xl font-semibold severity-low">{scan.low_count}</div>
            <div className="text-xs text-[#737373] mt-1">Low</div>
          </CardContent>
        </Card>
      </div>

      {/* Findings */}
      <Card>
        <CardHeader>
          <CardTitle>Findings ({sortedFindings.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {sortedFindings.length === 0 ? (
            <div className="text-center py-8 text-[#737373]">
              {scan.status === "running"
                ? "Scan in progress, findings will appear here..."
                : "No vulnerabilities found"}
            </div>
          ) : (
            <div className="space-y-3">
              {sortedFindings.map((finding) => (
                <div
                  key={finding.id}
                  className="border border-[#e5e5e5] rounded-lg overflow-hidden"
                >
                  <button
                    onClick={() => toggleFinding(finding.id)}
                    className="w-full flex items-center justify-between p-4 text-left hover:bg-[#fafafa] transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <Badge variant="severity" severity={finding.severity} />
                      <div>
                        <div className="font-medium">{finding.title}</div>
                        <div className="text-sm text-[#737373]">
                          {finding.category} · {finding.method} {finding.endpoint}
                        </div>
                      </div>
                    </div>
                    {expandedFindings.has(finding.id) ? (
                      <ChevronUp className="w-4 h-4 text-[#737373]" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-[#737373]" />
                    )}
                  </button>

                  {expandedFindings.has(finding.id) && (
                    <div className="px-4 pb-4 border-t border-[#e5e5e5] pt-4 space-y-4">
                      <div>
                        <div className="text-sm font-medium mb-1">Description</div>
                        <p className="text-sm text-[#737373]">{finding.description}</p>
                      </div>

                      {finding.business_impact && (
                        <div>
                          <div className="text-sm font-medium mb-1">Business Impact</div>
                          <p className="text-sm text-red-600">
                            Estimated: ${finding.business_impact.toLocaleString()}
                          </p>
                        </div>
                      )}

                      {finding.fix_suggestion && (
                        <div>
                          <div className="text-sm font-medium mb-1">Remediation</div>
                          <p className="text-sm text-[#737373]">{finding.fix_suggestion}</p>
                        </div>
                      )}

                      {finding.curl_command && (
                        <div>
                          <div className="text-sm font-medium mb-1">Proof of Concept</div>
                          <pre className="text-xs bg-[#1a1a1a] text-[#e5e5e5] p-3 rounded-lg overflow-x-auto">
                            {finding.curl_command}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
