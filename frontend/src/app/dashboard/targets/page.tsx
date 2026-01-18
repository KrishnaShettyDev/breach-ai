"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { api, type Target } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { Plus, Trash2, CheckCircle, AlertCircle, Copy, ExternalLink } from "lucide-react";

export default function TargetsPage() {
  const { getToken } = useAuth();
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [newUrl, setNewUrl] = useState("");
  const [newName, setNewName] = useState("");
  const [verifying, setVerifying] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    loadTargets();
  }, []);

  async function loadTargets() {
    try {
      const token = await getToken();
      if (!token) return;

      const data = await api.listTargets(token);
      setTargets(data);
    } catch (error) {
      console.error("Failed to load targets:", error);
    } finally {
      setLoading(false);
    }
  }

  const handleCreate = async () => {
    if (!newUrl) return;

    try {
      const token = await getToken();
      if (!token) return;

      const target = await api.createTarget(token, {
        url: newUrl,
        name: newName || new URL(newUrl).hostname,
      });

      setTargets([...targets, target]);
      setShowNew(false);
      setNewUrl("");
      setNewName("");
      setSuccess("Target created. Verify ownership to start scanning.");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Failed to create target");
    }
  };

  const handleVerify = async (targetId: string) => {
    setVerifying(targetId);
    setError(null);

    try {
      const token = await getToken();
      if (!token) return;

      const result = await api.verifyTarget(token, targetId, "dns");

      if (result.success) {
        setSuccess("Target verified successfully!");
        loadTargets();
      } else {
        setError(result.message);
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : "Verification failed");
    } finally {
      setVerifying(null);
    }
  };

  const handleDelete = async (targetId: string) => {
    if (!confirm("Delete this target?")) return;

    try {
      const token = await getToken();
      if (!token) return;

      await api.deleteTarget(token, targetId);
      setTargets(targets.filter((t) => t.id !== targetId));
      setSuccess("Target deleted");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Failed to delete target");
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSuccess("Copied to clipboard");
    setTimeout(() => setSuccess(null), 2000);
  };

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
          <h1 className="text-2xl font-semibold">Targets</h1>
          <p className="text-[#737373] mt-1">Manage your scan targets</p>
        </div>
        <Button onClick={() => setShowNew(true)}>
          <Plus className="w-4 h-4 mr-2" />
          Add Target
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

      {/* New Target Form */}
      {showNew && (
        <Card>
          <CardHeader>
            <CardTitle>Add New Target</CardTitle>
            <CardDescription>Enter the URL of the application you want to scan</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Input
              placeholder="https://example.com"
              value={newUrl}
              onChange={(e) => setNewUrl(e.target.value)}
            />
            <Input
              placeholder="Target name (optional)"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
            />
            <div className="flex gap-2">
              <Button onClick={handleCreate}>Add Target</Button>
              <Button variant="outline" onClick={() => setShowNew(false)}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Targets List */}
      {targets.length === 0 ? (
        <Card className="p-12 text-center">
          <p className="text-[#737373] mb-4">No targets yet</p>
          <Button onClick={() => setShowNew(true)}>Add your first target</Button>
        </Card>
      ) : (
        <div className="space-y-4">
          {targets.map((target) => (
            <Card key={target.id}>
              <CardContent className="pt-6">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold">{target.name}</h3>
                      {target.is_verified ? (
                        <Badge className="bg-green-100 text-green-700">Verified</Badge>
                      ) : (
                        <Badge className="bg-yellow-100 text-yellow-700">Unverified</Badge>
                      )}
                    </div>
                    <a
                      href={target.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-[#737373] hover:text-black flex items-center gap-1 mt-1"
                    >
                      {target.url}
                      <ExternalLink className="w-3 h-3" />
                    </a>
                    <p className="text-sm text-[#737373] mt-2">Added {formatDate(target.created_at)}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    {!target.is_verified && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleVerify(target.id)}
                        disabled={verifying === target.id}
                      >
                        {verifying === target.id ? "Verifying..." : "Verify"}
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(target.id)}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>

                {!target.is_verified && (
                  <div className="mt-4 p-4 bg-[#f5f5f5] rounded-lg">
                    <p className="text-sm font-medium mb-2">Verification Instructions</p>
                    <p className="text-sm text-[#737373] mb-3">
                      Add a DNS TXT record to verify ownership:
                    </p>
                    <div className="flex items-center gap-2 bg-white p-2 rounded border border-[#e5e5e5]">
                      <code className="text-xs flex-1 truncate">
                        _breach-verify.{new URL(target.url).hostname} TXT "{target.verification_token}"
                      </code>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(target.verification_token)}
                      >
                        <Copy className="w-3 h-3" />
                      </Button>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
