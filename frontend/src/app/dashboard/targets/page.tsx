"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { mutate } from "swr";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useTargets } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { Plus, Trash2, CheckCircle, AlertCircle, ExternalLink } from "lucide-react";
import Link from "next/link";

export default function TargetsPage() {
  const { getToken } = useAuth();
  const { data: targets, isLoading: loading } = useTargets();
  const [showNew, setShowNew] = useState(false);
  const [newUrl, setNewUrl] = useState("");
  const [newName, setNewName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const handleCreate = async () => {
    if (!newUrl) {
      setError("Please enter a URL");
      return;
    }

    setCreating(true);
    setError(null);

    try {
      const token = await getToken();
      if (!token) return;

      await api.createTarget(token, {
        url: newUrl.startsWith("http") ? newUrl : `https://${newUrl}`,
        name: newName || new URL(newUrl.startsWith("http") ? newUrl : `https://${newUrl}`).hostname,
      });

      // Revalidate the cache
      mutate("targets");
      setShowNew(false);
      setNewUrl("");
      setNewName("");
      setSuccess("Target added!");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Failed to add target");
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (targetId: string) => {
    if (!confirm("Delete this target?")) return;

    try {
      const token = await getToken();
      if (!token) return;

      await api.deleteTarget(token, targetId);
      mutate("targets");
      setSuccess("Target deleted");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Failed to delete target");
    }
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <Skeleton className="h-8 w-24" />
            <Skeleton className="h-4 w-40 mt-2" />
          </div>
          <Skeleton className="h-10 w-28" />
        </div>
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => (
            <Card key={i}>
              <CardContent className="pt-6">
                <Skeleton className="h-6 w-48" />
                <Skeleton className="h-4 w-64 mt-2" />
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
          <h1 className="text-2xl font-semibold">Targets</h1>
          <p className="text-[#737373] mt-1">Add websites to scan</p>
        </div>
        <Button onClick={() => setShowNew(true)}>
          <Plus className="w-4 h-4 mr-2" />
          Add Target
        </Button>
      </div>

      {/* Messages */}
      {error && (
        <div className="flex items-center gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span className="flex-1">{error}</span>
          <button onClick={() => setError(null)} className="text-red-500 hover:text-red-700">×</button>
        </div>
      )}
      {success && (
        <div className="flex items-center gap-2 p-4 bg-green-50 border border-green-200 rounded-lg text-green-700">
          <CheckCircle className="w-4 h-4 flex-shrink-0" />
          <span className="flex-1">{success}</span>
          <button onClick={() => setSuccess(null)} className="text-green-500 hover:text-green-700">×</button>
        </div>
      )}

      {/* New Target Form */}
      {showNew && (
        <Card>
          <CardHeader>
            <CardTitle>Add Target</CardTitle>
            <CardDescription>Enter the URL you want to scan</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Input
              placeholder="example.com"
              value={newUrl}
              onChange={(e) => setNewUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              autoFocus
            />
            <Input
              placeholder="Name (optional)"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
            />
            <div className="flex gap-2">
              <Button onClick={handleCreate} disabled={creating}>
                {creating ? "Adding..." : "Add"}
              </Button>
              <Button variant="outline" onClick={() => { setShowNew(false); setNewUrl(""); setNewName(""); }}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Targets List */}
      {(!targets || targets.length === 0) && !showNew ? (
        <Card className="p-12 text-center">
          <p className="text-[#737373] mb-4">No targets yet</p>
          <Button onClick={() => setShowNew(true)}>Add your first target</Button>
        </Card>
      ) : (
        <div className="space-y-3">
          {targets?.map((target) => (
            <Card key={target.id} className="hover:bg-[#fafafa] transition-colors">
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div className="min-w-0 flex-1">
                    <h3 className="font-semibold truncate">{target.name}</h3>
                    <a
                      href={target.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-[#737373] hover:text-black flex items-center gap-1 mt-1"
                    >
                      <span className="truncate">{target.url}</span>
                      <ExternalLink className="w-3 h-3 flex-shrink-0" />
                    </a>
                    <p className="text-xs text-[#a3a3a3] mt-2">Added {formatDate(target.created_at)}</p>
                  </div>
                  <div className="flex items-center gap-2 ml-4">
                    <Link href={`/dashboard/scans/new?target=${target.id}`}>
                      <Button size="sm">Scan</Button>
                    </Link>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(target.id)}
                      className="text-[#737373] hover:text-red-600"
                    >
                      <Trash2 className="w-4 h-4" />
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
