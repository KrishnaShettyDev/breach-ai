"use client";

import { useState, useEffect, useRef } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import useSWR from "swr";
import { useAuth } from "@clerk/nextjs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { api, type Scan, type Finding } from "@/lib/api";
import { formatDate, formatDuration } from "@/lib/utils";
import {
  ArrowLeft, Download, ExternalLink, ChevronDown, ChevronUp,
  AlertCircle, RefreshCw, Eye, Copy, Check, Terminal, Database,
  FileWarning, Zap, Shield, Bug, Globe, Server, Clock, Activity
} from "lucide-react";
import AttackDashboard from "@/components/scan/AttackDashboard";
import AttackTimeline from "@/components/scan/AttackTimeline";

const SCAN_PHASES: Record<string, { description: string }> = {
  recon: { description: "Discovering endpoints and attack surface" },
  injection: { description: "Testing for injection vulnerabilities" },
  testing: { description: "Executing security tests" },
  auth: { description: "Testing authentication mechanisms" },
  idor: { description: "Testing for access control issues" },
  scanning: { description: "Scan in progress" },
};

export default function ScanDetailPage() {
  const { getToken } = useAuth();
  const params = useParams();
  const scanId = params.id as string;
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const [showProof, setShowProof] = useState<Set<string>>(new Set());
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [newFindingIds, setNewFindingIds] = useState<Set<string>>(new Set());
  const [liveLog, setLiveLog] = useState<string[]>([]);
  const prevFindingsRef = useRef<string[]>([]);
  const logRef = useRef<HTMLDivElement>(null);

  const toggleProof = (id: string) => {
    setShowProof((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Use SWR with FAST polling for real-time updates
  const { data: scan, error, isLoading, mutate } = useSWR<Scan & { findings: Finding[] }>(
    `scan-${scanId}`,
    async () => {
      const token = await getToken();
      if (!token) throw new Error("Not authenticated");
      return api.getScan(token, scanId);
    },
    {
      refreshInterval: (data) => {
        // Poll every 1 second while scan is running for real-time feel
        if (data?.status === "running" || data?.status === "pending") {
          return 1000;
        }
        return 0;
      },
      revalidateOnFocus: false,
      errorRetryCount: 3,
      errorRetryInterval: 1000,
    }
  );

  // Track new findings and add live log entries
  useEffect(() => {
    if (scan?.findings) {
      const currentIds = scan.findings.map(f => f.id);
      const prevIds = prevFindingsRef.current;

      // Find new findings
      const newIds = currentIds.filter(id => !prevIds.includes(id));
      if (newIds.length > 0) {
        setNewFindingIds(prev => new Set([...prev, ...newIds]));

        // Add to live log
        newIds.forEach(id => {
          const finding = scan.findings.find(f => f.id === id);
          if (finding) {
            const logEntry = `[${new Date().toLocaleTimeString()}] FOUND: ${finding.severity.toUpperCase()} - ${finding.title}`;
            setLiveLog(prev => [...prev.slice(-50), logEntry]); // Keep last 50 entries
          }
        });

        // Clear "new" status after 5 seconds
        setTimeout(() => {
          setNewFindingIds(prev => {
            const next = new Set(prev);
            newIds.forEach(id => next.delete(id));
            return next;
          });
        }, 5000);
      }

      prevFindingsRef.current = currentIds;
    }
  }, [scan?.findings]);

  // Add phase change logs
  useEffect(() => {
    if (scan?.current_phase) {
      const phase = SCAN_PHASES[scan.current_phase.toLowerCase()] || SCAN_PHASES["injection"];
      const logEntry = `[${new Date().toLocaleTimeString()}] PHASE: ${scan.current_phase} - ${phase.description}`;
      setLiveLog(prev => {
        // Don't add duplicate phase entries
        if (prev[prev.length - 1]?.includes(`PHASE: ${scan.current_phase}`)) return prev;
        return [...prev.slice(-50), logEntry];
      });
    }
  }, [scan?.current_phase]);

  // Auto-scroll live log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [liveLog]);

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

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div>
          <Skeleton className="h-4 w-24 mb-2" />
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-4 w-48 mt-2" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {[...Array(5)].map((_, i) => (
            <Card key={i}>
              <CardContent className="pt-6 text-center">
                <Skeleton className="h-8 w-12 mx-auto" />
                <Skeleton className="h-3 w-16 mx-auto mt-2" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
        <p className="text-[#737373] mb-2">Failed to load scan</p>
        <p className="text-sm text-red-600 mb-4">{error.message}</p>
        <div className="flex gap-2 justify-center">
          <Button onClick={() => mutate()} variant="outline">
            <RefreshCw className="w-4 h-4 mr-2" />
            Retry
          </Button>
          <Link href="/dashboard/scans">
            <Button variant="outline">Back to Scans</Button>
          </Link>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <p className="text-[#737373]">Scan not found</p>
        <Link href="/dashboard/scans">
          <Button variant="outline" className="mt-4">Back to Scans</Button>
        </Link>
      </div>
    );
  }

  const sortedFindings = [...(scan.findings || [])].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (severityOrder[a.severity as keyof typeof severityOrder] || 5) -
           (severityOrder[b.severity as keyof typeof severityOrder] || 5);
  });

  const isRunning = scan.status === "running" || scan.status === "pending";

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
            <a href={scan.target_url} target="_blank" rel="noopener noreferrer">
              <ExternalLink className="w-4 h-4 text-[#a3a3a3] hover:text-black" />
            </a>
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
                  ? "bg-blue-100 text-blue-700 animate-pulse"
                  : scan.status === "pending"
                  ? "bg-yellow-100 text-yellow-700"
                  : scan.status === "failed"
                  ? "bg-red-100 text-red-700"
                  : ""
              }
            >
              {isRunning && <RefreshCw className="w-3 h-3 mr-1 animate-spin" />}
              {scan.status}
            </Badge>
          </div>
        </div>
        {scan.status === "completed" && (
          <a
            href={`${process.env.NEXT_PUBLIC_API_URL}/api/v1/scans/${scan.id}/export?format=html`}
            target="_blank"
            rel="noopener noreferrer"
          >
            <Button variant="outline">
              <Download className="w-4 h-4 mr-2" />
              Export
            </Button>
          </a>
        )}
      </div>

      {/* VISUAL ATTACK DASHBOARD - Show when running */}
      {isRunning && (
        <div className="space-y-4">
          {/* Main Attack Visualization */}
          <AttackDashboard
            targetUrl={scan.target_url}
            progress={scan.progress}
            currentPhase={scan.current_phase || "scanning"}
            findings={sortedFindings}
            isRunning={isRunning}
            endpointsTested={scan.progress}
            totalEndpoints={100}
          />

          {/* Attack Timeline */}
          <AttackTimeline
            findings={sortedFindings}
            startedAt={scan.started_at || undefined}
            currentPhase={scan.current_phase || "scanning"}
            progress={scan.progress}
            isRunning={isRunning}
          />

          {/* Live Activity Log */}
          <Card className="border border-[#333] bg-[#0a0a0a] text-white overflow-hidden">
            <CardHeader className="pb-2 border-b border-[#333]">
              <CardTitle className="text-sm flex items-center gap-2">
                <Activity className="w-4 h-4 text-green-400" />
                Live Activity Feed
                <span className="ml-auto text-xs text-[#737373] font-normal">
                  Updating every second
                </span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div
                ref={logRef}
                className="h-[150px] overflow-y-auto font-mono text-xs p-3 space-y-1"
              >
                {liveLog.length === 0 ? (
                  <div className="text-[#737373] text-center py-8">
                    Waiting for scan events...
                  </div>
                ) : (
                  liveLog.map((entry, idx) => (
                    <div
                      key={idx}
                      className={`${
                        entry.includes("CRITICAL") ? "text-red-400" :
                        entry.includes("HIGH") ? "text-orange-400" :
                        entry.includes("MEDIUM") ? "text-yellow-400" :
                        entry.includes("FOUND:") ? "text-green-400" :
                        entry.includes("PHASE:") ? "text-blue-400" :
                        "text-[#a3a3a3]"
                      } ${idx === liveLog.length - 1 ? "animate-pulse" : ""}`}
                    >
                      {entry}
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Stats - Compact when running, full when complete */}
      {!isRunning && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <Card>
            <CardContent className="pt-6 text-center">
              <div className="text-2xl font-semibold">{scan.findings_count}</div>
              <div className="text-xs text-[#737373] mt-1">Total</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6 text-center">
              <div className="text-2xl font-semibold text-red-600">{scan.critical_count}</div>
              <div className="text-xs text-[#737373] mt-1">Critical</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6 text-center">
              <div className="text-2xl font-semibold text-orange-600">{scan.high_count}</div>
              <div className="text-xs text-[#737373] mt-1">High</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6 text-center">
              <div className="text-2xl font-semibold text-yellow-600">{scan.medium_count}</div>
              <div className="text-xs text-[#737373] mt-1">Medium</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6 text-center">
              <div className="text-2xl font-semibold text-blue-600">{scan.low_count}</div>
              <div className="text-xs text-[#737373] mt-1">Low</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Findings */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Findings ({sortedFindings.length})
            {isRunning && sortedFindings.length > 0 && (
              <Badge className="bg-green-500 text-white animate-pulse">
                LIVE
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {sortedFindings.length === 0 ? (
            <div className="text-center py-8">
              {isRunning ? (
                <div className="space-y-3">
                  <Server className="w-12 h-12 mx-auto text-blue-500 animate-pulse" />
                  <p className="text-[#737373]">Scanning in progress...</p>
                  <p className="text-sm text-blue-600">Findings will appear here in real-time</p>
                </div>
              ) : (
                <p className="text-[#737373]">No vulnerabilities found</p>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              {sortedFindings.map((finding) => (
                <div
                  key={finding.id}
                  className={`border rounded-lg overflow-hidden transition-all duration-500 ${
                    newFindingIds.has(finding.id)
                      ? "border-green-500 bg-green-50 shadow-lg shadow-green-200"
                      : "border-[#e5e5e5]"
                  }`}
                >
                  <button
                    onClick={() => toggleFinding(finding.id)}
                    className="w-full flex items-center justify-between p-4 text-left hover:bg-[#fafafa] transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      {newFindingIds.has(finding.id) && (
                        <Badge className="bg-green-500 text-white text-xs animate-bounce">
                          NEW
                        </Badge>
                      )}
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
                      {finding.description && (
                        <div>
                          <div className="text-sm font-medium mb-1">Description</div>
                          <p className="text-sm text-[#737373]">{finding.description}</p>
                        </div>
                      )}

                      {/* Evidence Preview */}
                      {finding.evidence && (
                        <div>
                          <div className="text-sm font-medium mb-1">Evidence</div>
                          <pre className="text-xs bg-[#f5f5f5] p-3 rounded overflow-x-auto whitespace-pre-wrap max-h-32">
                            {finding.evidence}
                          </pre>
                        </div>
                      )}

                      {finding.fix_suggestion && (
                        <div>
                          <div className="text-sm font-medium mb-1">Remediation</div>
                          <p className="text-sm text-[#737373]">{finding.fix_suggestion}</p>
                        </div>
                      )}

                      {/* Show Proof Button */}
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => toggleProof(finding.id)}
                        className="flex items-center gap-2"
                      >
                        <Eye className="w-4 h-4" />
                        {showProof.has(finding.id) ? "Hide Proof" : "Show Proof"}
                      </Button>

                      {/* Proof Section */}
                      {showProof.has(finding.id) && (
                        <div className="space-y-4 mt-4 p-4 bg-[#0a0a0a] rounded-lg border border-[#333]">
                          <h4 className="text-white font-semibold flex items-center gap-2">
                            <FileWarning className="w-4 h-4 text-red-500" />
                            Vulnerability Proof
                          </h4>

                          {/* Endpoint */}
                          <div>
                            <div className="text-xs text-[#737373] mb-1">Vulnerable Endpoint</div>
                            <div className="flex items-center gap-2">
                              <code className="text-sm text-green-400 bg-[#1a1a1a] px-2 py-1 rounded flex-1">
                                {finding.method} {finding.endpoint}
                              </code>
                              <button
                                onClick={() => copyToClipboard(finding.endpoint, `endpoint-${finding.id}`)}
                                className="text-[#737373] hover:text-white"
                              >
                                {copiedId === `endpoint-${finding.id}` ? (
                                  <Check className="w-4 h-4 text-green-500" />
                                ) : (
                                  <Copy className="w-4 h-4" />
                                )}
                              </button>
                            </div>
                          </div>

                          {/* Parameter if exists */}
                          {finding.parameter && (
                            <div>
                              <div className="text-xs text-[#737373] mb-1">Vulnerable Parameter</div>
                              <code className="text-sm text-yellow-400 bg-[#1a1a1a] px-2 py-1 rounded block">
                                {finding.parameter}
                              </code>
                            </div>
                          )}

                          {/* Records Exposed */}
                          {(finding.records_exposed ?? 0) > 0 && (
                            <div>
                              <div className="text-xs text-[#737373] mb-1 flex items-center gap-1">
                                <Database className="w-3 h-3" />
                                Records Exposed
                              </div>
                              <div className="text-2xl font-bold text-red-500">
                                {finding.records_exposed?.toLocaleString()}
                              </div>
                            </div>
                          )}

                          {/* PII Fields */}
                          {finding.pii_fields && finding.pii_fields.length > 0 && (
                            <div>
                              <div className="text-xs text-[#737373] mb-1">Exposed PII Fields</div>
                              <div className="flex flex-wrap gap-1">
                                {finding.pii_fields.map((field, idx) => (
                                  <span
                                    key={idx}
                                    className="text-xs bg-red-900/50 text-red-300 px-2 py-1 rounded"
                                  >
                                    {field}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Impact Explanation */}
                          {finding.impact_explanation && (
                            <div>
                              <div className="text-xs text-[#737373] mb-1">Impact</div>
                              <p className="text-sm text-[#a3a3a3]">{finding.impact_explanation}</p>
                            </div>
                          )}

                          {/* cURL Command */}
                          {finding.curl_command && (
                            <div>
                              <div className="text-xs text-[#737373] mb-1 flex items-center gap-1">
                                <Terminal className="w-3 h-3" />
                                Reproduce with cURL
                              </div>
                              <div className="relative">
                                <pre className="text-xs bg-[#1a1a1a] text-[#e5e5e5] p-3 rounded-lg overflow-x-auto whitespace-pre-wrap pr-10">
                                  {finding.curl_command}
                                </pre>
                                <button
                                  onClick={() => copyToClipboard(finding.curl_command || "", `curl-${finding.id}`)}
                                  className="absolute top-2 right-2 text-[#737373] hover:text-white"
                                >
                                  {copiedId === `curl-${finding.id}` ? (
                                    <Check className="w-4 h-4 text-green-500" />
                                  ) : (
                                    <Copy className="w-4 h-4" />
                                  )}
                                </button>
                              </div>
                            </div>
                          )}

                          {/* References */}
                          {finding.references && finding.references.length > 0 && (
                            <div>
                              <div className="text-xs text-[#737373] mb-1">References</div>
                              <div className="space-y-1">
                                {finding.references.map((ref, idx) => (
                                  <a
                                    key={idx}
                                    href={ref}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-xs text-blue-400 hover:underline block truncate"
                                  >
                                    {ref}
                                  </a>
                                ))}
                              </div>
                            </div>
                          )}
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
