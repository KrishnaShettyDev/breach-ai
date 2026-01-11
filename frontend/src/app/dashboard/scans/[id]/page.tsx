'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@clerk/nextjs';
import { useParams } from 'next/navigation';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { api, ScanDetail, Finding } from '@/lib/api';
import { formatDate, getSeverityColor, getStatusColor } from '@/lib/utils';
import { cn } from '@/lib/utils';
import {
  Loader2,
  ArrowLeft,
  AlertTriangle,
  Shield,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  StopCircle,
} from 'lucide-react';
import Link from 'next/link';

export default function ScanDetailPage() {
  const { getToken } = useAuth();
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  useEffect(() => {
    loadScan();
    // Poll for updates if running
    const interval = setInterval(() => {
      if (scan?.status === 'running') {
        loadScan();
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [scanId, scan?.status]);

  async function loadScan() {
    try {
      const token = await getToken();
      if (!token) return;
      const [scanData, findingsData] = await Promise.all([
        api.getScan(token, scanId),
        api.getFindings(token, scanId),
      ]);
      setScan(scanData);
      setFindings(findingsData);
    } catch (err) {
      console.error('Failed to load scan:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleStop() {
    try {
      const token = await getToken();
      if (!token) return;
      await api.stopScan(token, scanId);
      loadScan();
    } catch (err) {
      console.error('Failed to stop scan:', err);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-neutral-400" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-neutral-600" />
        <h2 className="text-xl font-semibold mb-2">Scan not found</h2>
        <Link href="/dashboard/scans">
          <Button variant="outline">Back to Scans</Button>
        </Link>
      </div>
    );
  }

  const severityCounts = findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/dashboard/scans">
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-5 w-5" />
            </Button>
          </Link>
          <div>
            <h1 className="text-2xl font-bold">{scan.target_url}</h1>
            <p className="text-neutral-400 mt-1">
              {scan.scan_mode} mode · Started {formatDate(scan.created_at)}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <Badge className={cn('text-sm', getStatusColor(scan.status))}>{scan.status}</Badge>
          {scan.status === 'running' && (
            <Button variant="outline" onClick={handleStop} className="gap-2">
              <StopCircle className="h-4 w-4" />
              Stop Scan
            </Button>
          )}
        </div>
      </div>

      {/* Progress */}
      {scan.status === 'running' && (
        <Card>
          <CardContent className="py-6">
            <div className="flex items-center justify-between mb-2">
              <span className="font-medium">Scan Progress</span>
              <span className="text-neutral-400">{scan.progress}%</span>
            </div>
            <Progress value={scan.progress} className="h-2" />
          </CardContent>
        </Card>
      )}

      {/* Summary */}
      <div className="grid md:grid-cols-5 gap-4">
        <SummaryCard
          label="Critical"
          count={severityCounts.critical || 0}
          color="text-red-500 bg-red-500/10"
        />
        <SummaryCard
          label="High"
          count={severityCounts.high || 0}
          color="text-orange-500 bg-orange-500/10"
        />
        <SummaryCard
          label="Medium"
          count={severityCounts.medium || 0}
          color="text-yellow-500 bg-yellow-500/10"
        />
        <SummaryCard
          label="Low"
          count={severityCounts.low || 0}
          color="text-blue-500 bg-blue-500/10"
        />
        <SummaryCard
          label="Info"
          count={severityCounts.info || 0}
          color="text-gray-500 bg-gray-500/10"
        />
      </div>

      {/* Findings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Findings ({findings.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {findings.length === 0 ? (
            <div className="text-center py-8 text-neutral-400">
              {scan.status === 'running' ? (
                <p>Scanning in progress...</p>
              ) : (
                <p>No vulnerabilities found</p>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              {findings.map((finding) => (
                <div
                  key={finding.id}
                  className="border border-neutral-800 rounded-lg overflow-hidden"
                >
                  <button
                    onClick={() =>
                      setExpandedFinding(expandedFinding === finding.id ? null : finding.id)
                    }
                    className="w-full flex items-center justify-between p-4 text-left hover:bg-neutral-800/50 transition-colors"
                  >
                    <div className="flex items-center gap-4">
                      <Badge
                        variant={finding.severity as any}
                        className={getSeverityColor(finding.severity)}
                      >
                        {finding.severity.toUpperCase()}
                      </Badge>
                      <div>
                        <div className="font-medium">{finding.title}</div>
                        <div className="text-sm text-neutral-400">{finding.category}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {finding.cvss_score && (
                        <span className="text-sm text-neutral-400">
                          CVSS: {finding.cvss_score}
                        </span>
                      )}
                      {expandedFinding === finding.id ? (
                        <ChevronUp className="h-5 w-5 text-neutral-400" />
                      ) : (
                        <ChevronDown className="h-5 w-5 text-neutral-400" />
                      )}
                    </div>
                  </button>

                  {expandedFinding === finding.id && (
                    <div className="p-4 border-t border-neutral-800 bg-neutral-900/50 space-y-4">
                      <div>
                        <h4 className="text-sm font-medium text-neutral-400 mb-2">Description</h4>
                        <p className="text-sm">{finding.description}</p>
                      </div>

                      {finding.affected_url && (
                        <div>
                          <h4 className="text-sm font-medium text-neutral-400 mb-2">
                            Affected URL
                          </h4>
                          <a
                            href={finding.affected_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-sm text-blue-400 hover:underline flex items-center gap-1"
                          >
                            {finding.affected_url}
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </div>
                      )}

                      {finding.evidence && (
                        <div>
                          <h4 className="text-sm font-medium text-neutral-400 mb-2">Evidence</h4>
                          <pre className="text-sm bg-black p-3 rounded-lg overflow-x-auto font-mono">
                            {finding.evidence}
                          </pre>
                        </div>
                      )}

                      {finding.remediation && (
                        <div>
                          <h4 className="text-sm font-medium text-neutral-400 mb-2">
                            Remediation
                          </h4>
                          <p className="text-sm text-green-400">{finding.remediation}</p>
                        </div>
                      )}

                      <div className="flex gap-4 text-xs text-neutral-500">
                        {finding.cwe_id && <span>CWE: {finding.cwe_id}</span>}
                        <span>Found: {formatDate(finding.created_at)}</span>
                      </div>
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

function SummaryCard({
  label,
  count,
  color,
}: {
  label: string;
  count: number;
  color: string;
}) {
  return (
    <Card>
      <CardContent className="p-4 text-center">
        <div className={cn('text-3xl font-bold', color.split(' ')[0])}>{count}</div>
        <div className="text-sm text-neutral-400">{label}</div>
      </CardContent>
    </Card>
  );
}
