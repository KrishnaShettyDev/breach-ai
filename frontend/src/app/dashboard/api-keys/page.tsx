"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { mutate } from "swr";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useAPIKeys } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { Plus, Trash2, Copy, Key, CheckCircle, AlertCircle } from "lucide-react";

export default function APIKeysPage() {
  const { getToken } = useAuth();
  const { data: keys, isLoading: loading } = useAPIKeys();
  const [showNew, setShowNew] = useState(false);
  const [newName, setNewName] = useState("");
  const [newKey, setNewKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const handleCreate = async () => {
    if (!newName.trim()) {
      setError("Please enter a name for the API key");
      return;
    }

    setCreating(true);
    setError(null);

    try {
      const token = await getToken();
      if (!token) return;

      const result = await api.createAPIKey(token, { name: newName.trim() });
      setNewKey(result.raw_key);
      mutate("api-keys");
      setNewName("");
      setSuccess("API key created! Copy it now - you won't see it again.");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Failed to create API key");
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (keyId: string) => {
    if (!confirm("Delete this API key? Any applications using it will stop working.")) return;

    try {
      const token = await getToken();
      if (!token) return;

      await api.deleteAPIKey(token, keyId);
      mutate("api-keys");
      setSuccess("API key deleted");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Failed to delete API key");
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSuccess("Copied!");
    setTimeout(() => setSuccess(null), 2000);
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <Skeleton className="h-8 w-24" />
            <Skeleton className="h-4 w-64 mt-2" />
          </div>
          <Skeleton className="h-10 w-28" />
        </div>
        <div className="space-y-4">
          {[...Array(2)].map((_, i) => (
            <Card key={i}>
              <CardContent className="pt-6">
                <Skeleton className="h-6 w-48" />
                <Skeleton className="h-4 w-32 mt-2" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">API Keys</h1>
          <p className="text-[#737373] mt-1">Manage API keys for programmatic access</p>
        </div>
        <Button onClick={() => { setShowNew(true); setNewKey(null); }}>
          <Plus className="w-4 h-4 mr-2" />
          New Key
        </Button>
      </div>

      {/* Messages */}
      {error && (
        <div className="flex items-center gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          <AlertCircle className="w-4 h-4" />
          {error}
          <button onClick={() => setError(null)} className="ml-auto text-red-500 hover:text-red-700">×</button>
        </div>
      )}
      {success && (
        <div className="flex items-center gap-2 p-4 bg-green-50 border border-green-200 rounded-lg text-green-700">
          <CheckCircle className="w-4 h-4" />
          {success}
          <button onClick={() => setSuccess(null)} className="ml-auto text-green-500 hover:text-green-700">×</button>
        </div>
      )}

      {/* New Key Form */}
      {showNew && (
        <Card>
          <CardHeader>
            <CardTitle>Create API Key</CardTitle>
            <CardDescription>API keys allow programmatic access to the BREACH API</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {newKey ? (
              <div className="space-y-4">
                <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                  <p className="text-sm font-medium text-yellow-800 mb-2">
                    Copy your API key now. You won't see it again!
                  </p>
                  <div className="flex items-center gap-2 bg-white p-3 rounded border border-yellow-300 font-mono text-sm">
                    <code className="flex-1 break-all">{newKey}</code>
                    <Button variant="ghost" size="sm" onClick={() => copyToClipboard(newKey)}>
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
                <Button variant="outline" onClick={() => { setShowNew(false); setNewKey(null); }}>
                  Done
                </Button>
              </div>
            ) : (
              <>
                <Input
                  placeholder="API key name (e.g., CI/CD Pipeline)"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleCreate()}
                  autoFocus
                />
                <div className="flex gap-2">
                  <Button onClick={handleCreate} disabled={creating}>
                    {creating ? "Creating..." : "Create Key"}
                  </Button>
                  <Button variant="outline" onClick={() => setShowNew(false)}>
                    Cancel
                  </Button>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      )}

      {/* Keys List */}
      {(!keys || keys.length === 0) && !showNew ? (
        <Card className="p-12 text-center">
          <Key className="w-12 h-12 mx-auto text-[#a3a3a3] mb-4" />
          <p className="text-[#737373] mb-4">No API keys yet</p>
          <Button onClick={() => setShowNew(true)}>Create your first API key</Button>
        </Card>
      ) : (
        <div className="space-y-4">
          {keys?.map((key) => (
            <Card key={key.id}>
              <CardContent className="pt-6">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <Key className="w-4 h-4 text-[#737373]" />
                      <h3 className="font-semibold">{key.name}</h3>
                    </div>
                    <div className="mt-2 font-mono text-sm text-[#737373]">
                      {key.key_prefix}••••••••
                    </div>
                    <div className="flex items-center gap-4 mt-2 text-sm text-[#737373]">
                      <span>Created {formatDate(key.created_at)}</span>
                      {key.last_used_at && <span>Last used {formatDate(key.last_used_at)}</span>}
                      {key.expires_at && (
                        <Badge variant="outline">Expires {formatDate(key.expires_at)}</Badge>
                      )}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleDelete(key.id)}
                    className="text-red-600 hover:text-red-700 hover:bg-red-50"
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Usage */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Usage</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-[#1a1a1a] text-white p-4 rounded-lg font-mono text-sm overflow-x-auto">
            <code>curl -H "Authorization: Bearer YOUR_API_KEY" \</code>
            <br />
            <code>  {process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/v1/scans</code>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
