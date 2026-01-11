'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@clerk/nextjs';
import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { api, Target } from '@/lib/api';
import { formatRelativeTime } from '@/lib/utils';
import {
  Target as TargetIcon,
  Plus,
  Trash2,
  ExternalLink,
  CheckCircle,
  XCircle,
  Loader2,
} from 'lucide-react';

export default function TargetsPage() {
  const { getToken } = useAuth();
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newTarget, setNewTarget] = useState({ name: '', url: '' });

  useEffect(() => {
    loadTargets();
  }, []);

  async function loadTargets() {
    try {
      const token = await getToken();
      if (!token) return;
      const data = await api.listTargets(token);
      setTargets(data);
    } catch (err) {
      console.error('Failed to load targets:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    try {
      const token = await getToken();
      if (!token) return;
      await api.createTarget(token, newTarget);
      setNewTarget({ name: '', url: '' });
      setShowForm(false);
      loadTargets();
    } catch (err) {
      console.error('Failed to create target:', err);
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(targetId: string) {
    if (!confirm('Are you sure you want to delete this target?')) return;
    try {
      const token = await getToken();
      if (!token) return;
      await api.deleteTarget(token, targetId);
      loadTargets();
    } catch (err) {
      console.error('Failed to delete target:', err);
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
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Targets</h1>
          <p className="text-neutral-400 mt-1">Manage your scan targets</p>
        </div>
        <Button onClick={() => setShowForm(!showForm)} className="gap-2">
          <Plus className="h-4 w-4" />
          Add Target
        </Button>
      </div>

      {/* Add Target Form */}
      {showForm && (
        <Card>
          <CardHeader>
            <CardTitle>Add New Target</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleCreate} className="space-y-4">
              <div className="grid md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-neutral-400 block mb-2">Name</label>
                  <Input
                    placeholder="My Website"
                    value={newTarget.name}
                    onChange={(e) => setNewTarget({ ...newTarget, name: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <label className="text-sm text-neutral-400 block mb-2">URL</label>
                  <Input
                    placeholder="https://example.com"
                    value={newTarget.url}
                    onChange={(e) => setNewTarget({ ...newTarget, url: e.target.value })}
                    required
                  />
                </div>
              </div>
              <div className="flex gap-2">
                <Button type="submit" disabled={creating}>
                  {creating && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Add Target
                </Button>
                <Button type="button" variant="outline" onClick={() => setShowForm(false)}>
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Targets List */}
      {targets.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <TargetIcon className="h-12 w-12 mx-auto mb-4 text-neutral-600" />
            <h3 className="font-semibold mb-2">No targets yet</h3>
            <p className="text-neutral-400 mb-4">Add a target to start scanning</p>
            <Button onClick={() => setShowForm(true)}>Add Your First Target</Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {targets.map((target) => (
            <Card key={target.id} className="hover:border-neutral-700 transition-colors">
              <CardContent className="p-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="p-3 rounded-lg bg-neutral-800">
                      <TargetIcon className="h-5 w-5 text-neutral-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold">{target.name}</h3>
                        {target.is_verified ? (
                          <CheckCircle className="h-4 w-4 text-green-500" />
                        ) : (
                          <XCircle className="h-4 w-4 text-neutral-500" />
                        )}
                      </div>
                      <a
                        href={target.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-sm text-neutral-400 hover:text-white flex items-center gap-1"
                      >
                        {target.url}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <Badge variant="secondary">{target.scan_type}</Badge>
                      {target.last_scanned_at && (
                        <p className="text-xs text-neutral-500 mt-1">
                          Last scan: {formatRelativeTime(target.last_scanned_at)}
                        </p>
                      )}
                    </div>

                    <Link href={`/dashboard/scans/new?target=${target.id}`}>
                      <Button size="sm">Scan</Button>
                    </Link>

                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => handleDelete(target.id)}
                      className="text-neutral-400 hover:text-red-500"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
