'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@clerk/nextjs';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { api, ApiKey } from '@/lib/api';
import { formatDate, formatRelativeTime } from '@/lib/utils';
import { Key, Plus, Trash2, Copy, Check, Loader2, AlertTriangle } from 'lucide-react';

export default function ApiKeysPage() {
  const { getToken } = useAuth();
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    loadApiKeys();
  }, []);

  async function loadApiKeys() {
    try {
      const token = await getToken();
      if (!token) return;
      const data = await api.listApiKeys(token);
      setApiKeys(data);
    } catch (err) {
      console.error('Failed to load API keys:', err);
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
      const result = await api.createApiKey(token, { name: newKeyName });
      setNewKey(result.key || null);
      setNewKeyName('');
      loadApiKeys();
    } catch (err) {
      console.error('Failed to create API key:', err);
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(keyId: string) {
    if (!confirm('Are you sure you want to revoke this API key? This cannot be undone.')) return;
    try {
      const token = await getToken();
      if (!token) return;
      await api.revokeApiKey(token, keyId);
      loadApiKeys();
    } catch (err) {
      console.error('Failed to revoke API key:', err);
    }
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
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
          <h1 className="text-2xl font-bold">API Keys</h1>
          <p className="text-neutral-400 mt-1">Manage API keys for programmatic access</p>
        </div>
        <Button onClick={() => setShowForm(!showForm)} className="gap-2">
          <Plus className="h-4 w-4" />
          Create Key
        </Button>
      </div>

      {/* New Key Created */}
      {newKey && (
        <Card className="border-green-500/30 bg-green-500/5">
          <CardContent className="py-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-lg bg-green-500/10">
                <Check className="h-6 w-6 text-green-500" />
              </div>
              <div className="flex-1">
                <h3 className="font-semibold text-green-500">API Key Created</h3>
                <p className="text-sm text-neutral-400 mt-1">
                  Copy this key now. You won't be able to see it again!
                </p>
                <div className="flex items-center gap-2 mt-3">
                  <code className="flex-1 bg-black px-4 py-2 rounded font-mono text-sm">
                    {newKey}
                  </code>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => copyToClipboard(newKey)}
                    className="gap-2"
                  >
                    {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                    {copied ? 'Copied!' : 'Copy'}
                  </Button>
                </div>
              </div>
              <Button variant="ghost" size="sm" onClick={() => setNewKey(null)}>
                Dismiss
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Create Form */}
      {showForm && !newKey && (
        <Card>
          <CardHeader>
            <CardTitle>Create New API Key</CardTitle>
            <CardDescription>
              API keys allow you to access BREACH.AI from your CI/CD pipeline or scripts.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="text-sm text-neutral-400 block mb-2">Key Name</label>
                <Input
                  placeholder="e.g., CI Pipeline, GitHub Actions"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  required
                />
              </div>
              <div className="flex gap-2">
                <Button type="submit" disabled={creating}>
                  {creating && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Create Key
                </Button>
                <Button type="button" variant="outline" onClick={() => setShowForm(false)}>
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* API Keys List */}
      {apiKeys.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Key className="h-12 w-12 mx-auto mb-4 text-neutral-600" />
            <h3 className="font-semibold mb-2">No API keys</h3>
            <p className="text-neutral-400 mb-4">Create an API key for programmatic access</p>
            <Button onClick={() => setShowForm(true)}>Create Your First Key</Button>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Active Keys</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {apiKeys.map((key) => (
                <div
                  key={key.id}
                  className="flex items-center justify-between p-4 rounded-lg border border-neutral-800"
                >
                  <div className="flex items-center gap-4">
                    <div className="p-2 rounded bg-neutral-800">
                      <Key className="h-5 w-5 text-neutral-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{key.name}</span>
                        {!key.is_active && (
                          <Badge variant="secondary" className="text-xs">
                            Revoked
                          </Badge>
                        )}
                      </div>
                      <div className="text-sm text-neutral-400 font-mono">{key.key_prefix}...</div>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="text-right text-sm">
                      <div className="text-neutral-400">
                        Created {formatRelativeTime(key.created_at)}
                      </div>
                      {key.last_used_at && (
                        <div className="text-neutral-500">
                          Last used {formatRelativeTime(key.last_used_at)}
                        </div>
                      )}
                    </div>

                    {key.is_active && (
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleRevoke(key.id)}
                        className="text-neutral-400 hover:text-red-500"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Usage Example */}
      <Card>
        <CardHeader>
          <CardTitle>Usage Example</CardTitle>
          <CardDescription>Use your API key to authenticate requests</CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="bg-black p-4 rounded-lg overflow-x-auto font-mono text-sm">
            {`curl -X POST https://api.breach.ai/api/v1/scans \\
  -H "X-API-Key: breach_your_api_key_here" \\
  -H "Content-Type: application/json" \\
  -d '{"target_id": "uuid", "scan_mode": "standard"}'`}
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}
