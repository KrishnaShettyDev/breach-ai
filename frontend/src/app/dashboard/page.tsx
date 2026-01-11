'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@clerk/nextjs';
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { api, Scan, Target } from '@/lib/api';
import { formatRelativeTime, getStatusColor } from '@/lib/utils';
import {
  Target as TargetIcon,
  Scan as ScanIcon,
  AlertTriangle,
  Shield,
  Plus,
  ArrowRight,
} from 'lucide-react';

export default function DashboardPage() {
  const { getToken } = useAuth();
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const token = await getToken();
        if (!token) return;

        const [targetsData, scansData] = await Promise.all([
          api.listTargets(token),
          api.listScans(token),
        ]);

        setTargets(targetsData);
        setScans(scansData);
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [getToken]);

  const runningScans = scans.filter((s) => s.status === 'running');
  const recentScans = scans.slice(0, 5);
  const totalFindings = scans.reduce((acc, s) => acc + s.findings_count, 0);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin h-8 w-8 border-2 border-red-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-neutral-400 mt-1">Overview of your security posture</p>
        </div>
        <Link href="/dashboard/scans/new">
          <Button className="gap-2">
            <Plus className="h-4 w-4" />
            New Scan
          </Button>
        </Link>
      </div>

      {/* Stats */}
      <div className="grid md:grid-cols-4 gap-4">
        <StatsCard
          title="Total Targets"
          value={targets.length}
          icon={<TargetIcon className="h-5 w-5" />}
        />
        <StatsCard
          title="Total Scans"
          value={scans.length}
          icon={<ScanIcon className="h-5 w-5" />}
        />
        <StatsCard
          title="Running Scans"
          value={runningScans.length}
          icon={<Shield className="h-5 w-5" />}
          highlight={runningScans.length > 0}
        />
        <StatsCard
          title="Total Findings"
          value={totalFindings}
          icon={<AlertTriangle className="h-5 w-5" />}
          highlight={totalFindings > 0}
        />
      </div>

      {/* Running Scans */}
      {runningScans.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <div className="h-2 w-2 bg-blue-500 rounded-full animate-pulse" />
              Running Scans
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {runningScans.map((scan) => (
              <div key={scan.id} className="flex items-center gap-4">
                <div className="flex-1">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium">{scan.target_url}</span>
                    <span className="text-sm text-neutral-400">{scan.progress}%</span>
                  </div>
                  <Progress value={scan.progress} />
                </div>
                <Link href={`/dashboard/scans/${scan.id}`}>
                  <Button variant="ghost" size="sm">
                    View
                    <ArrowRight className="h-4 w-4 ml-1" />
                  </Button>
                </Link>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Recent Scans */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Recent Scans</CardTitle>
          <Link href="/dashboard/scans">
            <Button variant="ghost" size="sm">
              View All
              <ArrowRight className="h-4 w-4 ml-1" />
            </Button>
          </Link>
        </CardHeader>
        <CardContent>
          {recentScans.length === 0 ? (
            <div className="text-center py-8 text-neutral-400">
              <ScanIcon className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No scans yet</p>
              <Link href="/dashboard/scans/new">
                <Button variant="outline" size="sm" className="mt-4">
                  Start Your First Scan
                </Button>
              </Link>
            </div>
          ) : (
            <div className="space-y-3">
              {recentScans.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/dashboard/scans/${scan.id}`}
                  className="flex items-center justify-between p-3 rounded-lg border border-neutral-800 hover:border-neutral-700 transition-colors"
                >
                  <div className="flex items-center gap-4">
                    <ScanIcon className="h-5 w-5 text-neutral-400" />
                    <div>
                      <div className="font-medium">{scan.target_url}</div>
                      <div className="text-sm text-neutral-400">
                        {formatRelativeTime(scan.created_at)}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    {scan.findings_count > 0 && (
                      <Badge variant="destructive">{scan.findings_count} findings</Badge>
                    )}
                    <Badge className={getStatusColor(scan.status)}>{scan.status}</Badge>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <div className="grid md:grid-cols-2 gap-4">
        <Card className="hover:border-neutral-700 transition-colors">
          <Link href="/dashboard/targets">
            <CardContent className="p-6 flex items-center gap-4">
              <div className="p-3 rounded-lg bg-red-500/10">
                <TargetIcon className="h-6 w-6 text-red-500" />
              </div>
              <div>
                <h3 className="font-semibold">Manage Targets</h3>
                <p className="text-sm text-neutral-400">Add and configure scan targets</p>
              </div>
              <ArrowRight className="h-5 w-5 ml-auto text-neutral-400" />
            </CardContent>
          </Link>
        </Card>

        <Card className="hover:border-neutral-700 transition-colors">
          <Link href="/dashboard/api-keys">
            <CardContent className="p-6 flex items-center gap-4">
              <div className="p-3 rounded-lg bg-blue-500/10">
                <Shield className="h-6 w-6 text-blue-500" />
              </div>
              <div>
                <h3 className="font-semibold">API Access</h3>
                <p className="text-sm text-neutral-400">Manage API keys for CI/CD integration</p>
              </div>
              <ArrowRight className="h-5 w-5 ml-auto text-neutral-400" />
            </CardContent>
          </Link>
        </Card>
      </div>
    </div>
  );
}

function StatsCard({
  title,
  value,
  icon,
  highlight = false,
}: {
  title: string;
  value: number;
  icon: React.ReactNode;
  highlight?: boolean;
}) {
  return (
    <Card className={highlight ? 'border-red-500/30' : ''}>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-neutral-400">{title}</p>
            <p className="text-3xl font-bold mt-1">{value}</p>
          </div>
          <div className={`p-3 rounded-lg ${highlight ? 'bg-red-500/10 text-red-500' : 'bg-neutral-800 text-neutral-400'}`}>
            {icon}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
