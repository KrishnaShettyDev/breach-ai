'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@clerk/nextjs';
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { api, Scan } from '@/lib/api';
import { formatRelativeTime, getStatusColor } from '@/lib/utils';
import { Scan as ScanIcon, Plus, Loader2, ArrowRight, AlertTriangle } from 'lucide-react';

export default function ScansPage() {
  const { getToken } = useAuth();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScans();
    // Poll for updates on running scans
    const interval = setInterval(loadScans, 5000);
    return () => clearInterval(interval);
  }, []);

  async function loadScans() {
    try {
      const token = await getToken();
      if (!token) return;
      const data = await api.listScans(token);
      setScans(data);
    } catch (err) {
      console.error('Failed to load scans:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleStop(scanId: string) {
    try {
      const token = await getToken();
      if (!token) return;
      await api.stopScan(token, scanId);
      loadScans();
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

  const runningScans = scans.filter((s) => s.status === 'running');
  const completedScans = scans.filter((s) => s.status !== 'running');

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scans</h1>
          <p className="text-neutral-400 mt-1">View and manage security scans</p>
        </div>
        <Link href="/dashboard/scans/new">
          <Button className="gap-2">
            <Plus className="h-4 w-4" />
            New Scan
          </Button>
        </Link>
      </div>

      {/* Running Scans */}
      {runningScans.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <div className="h-2 w-2 bg-blue-500 rounded-full animate-pulse" />
              Running Scans ({runningScans.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {runningScans.map((scan) => (
              <div
                key={scan.id}
                className="flex items-center gap-4 p-4 rounded-lg border border-neutral-800"
              >
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium">{scan.target_url}</span>
                    <span className="text-sm text-neutral-400">{scan.progress}%</span>
                  </div>
                  <Progress value={scan.progress} />
                  <div className="flex items-center gap-4 mt-2 text-sm text-neutral-400">
                    <span>Mode: {scan.scan_mode}</span>
                    <span>Findings: {scan.findings_count}</span>
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => handleStop(scan.id)}>
                    Stop
                  </Button>
                  <Link href={`/dashboard/scans/${scan.id}`}>
                    <Button size="sm">View</Button>
                  </Link>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* All Scans */}
      {scans.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <ScanIcon className="h-12 w-12 mx-auto mb-4 text-neutral-600" />
            <h3 className="font-semibold mb-2">No scans yet</h3>
            <p className="text-neutral-400 mb-4">Start a scan to find vulnerabilities</p>
            <Link href="/dashboard/scans/new">
              <Button>Start Your First Scan</Button>
            </Link>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Scan History</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {completedScans.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/dashboard/scans/${scan.id}`}
                  className="flex items-center justify-between p-4 rounded-lg border border-neutral-800 hover:border-neutral-700 transition-colors"
                >
                  <div className="flex items-center gap-4">
                    <ScanIcon className="h-5 w-5 text-neutral-400" />
                    <div>
                      <div className="font-medium">{scan.target_url}</div>
                      <div className="text-sm text-neutral-400">
                        {formatRelativeTime(scan.created_at)} · {scan.scan_mode} mode
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    {scan.findings_count > 0 && (
                      <div className="flex items-center gap-1 text-orange-500">
                        <AlertTriangle className="h-4 w-4" />
                        <span className="text-sm font-medium">{scan.findings_count}</span>
                      </div>
                    )}
                    <Badge className={getStatusColor(scan.status)}>{scan.status}</Badge>
                    <ArrowRight className="h-4 w-4 text-neutral-400" />
                  </div>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
