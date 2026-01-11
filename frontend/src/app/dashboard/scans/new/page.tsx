'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@clerk/nextjs';
import { useRouter, useSearchParams } from 'next/navigation';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { api, Target } from '@/lib/api';
import { cn } from '@/lib/utils';
import { Loader2, Target as TargetIcon, Zap, Shield, AlertTriangle } from 'lucide-react';

const scanModes = [
  {
    id: 'quick',
    name: 'Quick Scan',
    description: 'Fast reconnaissance and basic vulnerability checks',
    icon: Zap,
    duration: '~5 minutes',
  },
  {
    id: 'standard',
    name: 'Standard Scan',
    description: 'Comprehensive testing with all attack modules',
    icon: Shield,
    duration: '~15 minutes',
  },
  {
    id: 'deep',
    name: 'Deep Scan',
    description: 'Thorough testing with AI-powered attack chaining',
    icon: AlertTriangle,
    duration: '~30 minutes',
  },
];

export default function NewScanPage() {
  const { getToken } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const preselectedTarget = searchParams.get('target');

  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<string>(preselectedTarget || '');
  const [selectedMode, setSelectedMode] = useState('standard');
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);

  useEffect(() => {
    async function loadTargets() {
      try {
        const token = await getToken();
        if (!token) return;
        const data = await api.listTargets(token);
        setTargets(data);
        if (data.length > 0 && !selectedTarget) {
          setSelectedTarget(data[0].id);
        }
      } catch (err) {
        console.error('Failed to load targets:', err);
      } finally {
        setLoading(false);
      }
    }
    loadTargets();
  }, []);

  async function handleStartScan() {
    if (!selectedTarget) return;
    setStarting(true);
    try {
      const token = await getToken();
      if (!token) return;
      const scan = await api.startScan(token, {
        target_id: selectedTarget,
        scan_mode: selectedMode,
      });
      router.push(`/dashboard/scans/${scan.id}`);
    } catch (err) {
      console.error('Failed to start scan:', err);
      setStarting(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-neutral-400" />
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold">New Scan</h1>
        <p className="text-neutral-400 mt-1">Configure and start a security scan</p>
      </div>

      {/* Select Target */}
      <Card>
        <CardHeader>
          <CardTitle>Select Target</CardTitle>
          <CardDescription>Choose the target you want to scan</CardDescription>
        </CardHeader>
        <CardContent>
          {targets.length === 0 ? (
            <div className="text-center py-8">
              <TargetIcon className="h-10 w-10 mx-auto mb-4 text-neutral-600" />
              <p className="text-neutral-400 mb-4">No targets available</p>
              <Button onClick={() => router.push('/dashboard/targets')}>Add a Target</Button>
            </div>
          ) : (
            <div className="grid gap-3">
              {targets.map((target) => (
                <button
                  key={target.id}
                  onClick={() => setSelectedTarget(target.id)}
                  className={cn(
                    'flex items-center gap-4 p-4 rounded-lg border text-left transition-colors',
                    selectedTarget === target.id
                      ? 'border-red-500 bg-red-500/5'
                      : 'border-neutral-800 hover:border-neutral-700'
                  )}
                >
                  <div className="p-2 rounded bg-neutral-800">
                    <TargetIcon className="h-5 w-5 text-neutral-400" />
                  </div>
                  <div>
                    <div className="font-medium">{target.name}</div>
                    <div className="text-sm text-neutral-400">{target.url}</div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Select Mode */}
      <Card>
        <CardHeader>
          <CardTitle>Scan Mode</CardTitle>
          <CardDescription>Choose how thorough the scan should be</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3">
            {scanModes.map((mode) => (
              <button
                key={mode.id}
                onClick={() => setSelectedMode(mode.id)}
                className={cn(
                  'flex items-center gap-4 p-4 rounded-lg border text-left transition-colors',
                  selectedMode === mode.id
                    ? 'border-red-500 bg-red-500/5'
                    : 'border-neutral-800 hover:border-neutral-700'
                )}
              >
                <div
                  className={cn(
                    'p-2 rounded',
                    selectedMode === mode.id ? 'bg-red-500/10 text-red-500' : 'bg-neutral-800 text-neutral-400'
                  )}
                >
                  <mode.icon className="h-5 w-5" />
                </div>
                <div className="flex-1">
                  <div className="font-medium">{mode.name}</div>
                  <div className="text-sm text-neutral-400">{mode.description}</div>
                </div>
                <div className="text-sm text-neutral-500">{mode.duration}</div>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Start Button */}
      <div className="flex justify-end gap-4">
        <Button variant="outline" onClick={() => router.back()}>
          Cancel
        </Button>
        <Button
          onClick={handleStartScan}
          disabled={!selectedTarget || starting}
          className="gap-2"
        >
          {starting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Starting...
            </>
          ) : (
            <>
              <Shield className="h-4 w-4" />
              Start Scan
            </>
          )}
        </Button>
      </div>
    </div>
  );
}
