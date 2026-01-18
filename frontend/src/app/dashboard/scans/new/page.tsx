"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, type Target } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Check, Plus, AlertCircle } from "lucide-react";

const scanModes = [
  {
    id: "quick",
    name: "Quick",
    description: "Fast scan covering common vulnerabilities",
    time: "~5 min",
  },
  {
    id: "standard",
    name: "Standard",
    description: "Balanced coverage of OWASP Top 10",
    time: "~15 min",
  },
  {
    id: "deep",
    name: "Deep",
    description: "Comprehensive security assessment",
    time: "~30 min",
  },
];

export default function NewScanPage() {
  const { getToken } = useAuth();
  const router = useRouter();
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);
  const [selectedMode, setSelectedMode] = useState("standard");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // New target form
  const [showNewTarget, setShowNewTarget] = useState(false);
  const [newTargetUrl, setNewTargetUrl] = useState("");
  const [newTargetName, setNewTargetName] = useState("");

  useEffect(() => {
    async function loadTargets() {
      try {
        const token = await getToken();
        if (!token) return;

        const data = await api.listTargets(token);
        setTargets(data);

        // Auto-select first verified target
        const verified = data.find((t) => t.is_verified);
        if (verified) {
          setSelectedTarget(verified.id);
        }
      } catch (error) {
        console.error("Failed to load targets:", error);
      } finally {
        setLoading(false);
      }
    }

    loadTargets();
  }, [getToken]);

  const handleCreateTarget = async () => {
    if (!newTargetUrl) return;

    try {
      const token = await getToken();
      if (!token) return;

      const target = await api.createTarget(token, {
        url: newTargetUrl,
        name: newTargetName || new URL(newTargetUrl).hostname,
      });

      setTargets([...targets, target]);
      setSelectedTarget(target.id);
      setShowNewTarget(false);
      setNewTargetUrl("");
      setNewTargetName("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Failed to create target");
    }
  };

  const handleStartScan = async () => {
    if (!selectedTarget) {
      setError("Please select a target");
      return;
    }

    const target = targets.find((t) => t.id === selectedTarget);
    if (!target?.is_verified) {
      setError("Target must be verified before scanning. Go to Targets to verify.");
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const token = await getToken();
      if (!token) return;

      const scan = await api.createScan(token, {
        target_id: selectedTarget,
        mode: selectedMode,
      });

      router.push(`/dashboard/scans/${scan.id}`);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Failed to start scan");
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#737373]">Loading...</div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">New Scan</h1>
        <p className="text-[#737373] mt-1">Configure and start a security scan</p>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          <AlertCircle className="w-4 h-4" />
          {error}
        </div>
      )}

      {/* Target Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Select Target</CardTitle>
          <CardDescription>Choose a verified target to scan</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {targets.map((target) => (
            <button
              key={target.id}
              onClick={() => setSelectedTarget(target.id)}
              className={cn(
                "w-full flex items-center justify-between p-4 border rounded-lg text-left transition-colors",
                selectedTarget === target.id
                  ? "border-black bg-[#f5f5f5]"
                  : "border-[#e5e5e5] hover:bg-[#fafafa]"
              )}
            >
              <div>
                <div className="font-medium">{target.name}</div>
                <div className="text-sm text-[#737373]">{target.url}</div>
              </div>
              <div className="flex items-center gap-2">
                {target.is_verified ? (
                  <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded">
                    Verified
                  </span>
                ) : (
                  <span className="text-xs bg-yellow-100 text-yellow-700 px-2 py-1 rounded">
                    Unverified
                  </span>
                )}
                {selectedTarget === target.id && (
                  <Check className="w-4 h-4" />
                )}
              </div>
            </button>
          ))}

          {!showNewTarget ? (
            <Button
              variant="outline"
              className="w-full"
              onClick={() => setShowNewTarget(true)}
            >
              <Plus className="w-4 h-4 mr-2" />
              Add New Target
            </Button>
          ) : (
            <div className="space-y-3 p-4 border border-[#e5e5e5] rounded-lg">
              <Input
                placeholder="https://example.com"
                value={newTargetUrl}
                onChange={(e) => setNewTargetUrl(e.target.value)}
              />
              <Input
                placeholder="Target name (optional)"
                value={newTargetName}
                onChange={(e) => setNewTargetName(e.target.value)}
              />
              <div className="flex gap-2">
                <Button onClick={handleCreateTarget}>Add Target</Button>
                <Button variant="outline" onClick={() => setShowNewTarget(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan Mode */}
      <Card>
        <CardHeader>
          <CardTitle>Scan Mode</CardTitle>
          <CardDescription>Choose the depth of the security scan</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {scanModes.map((mode) => (
            <button
              key={mode.id}
              onClick={() => setSelectedMode(mode.id)}
              className={cn(
                "w-full flex items-center justify-between p-4 border rounded-lg text-left transition-colors",
                selectedMode === mode.id
                  ? "border-black bg-[#f5f5f5]"
                  : "border-[#e5e5e5] hover:bg-[#fafafa]"
              )}
            >
              <div>
                <div className="font-medium">{mode.name}</div>
                <div className="text-sm text-[#737373]">{mode.description}</div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-sm text-[#737373]">{mode.time}</span>
                {selectedMode === mode.id && <Check className="w-4 h-4" />}
              </div>
            </button>
          ))}
        </CardContent>
      </Card>

      {/* Submit */}
      <Button
        size="lg"
        className="w-full"
        onClick={handleStartScan}
        disabled={submitting || !selectedTarget}
      >
        {submitting ? "Starting Scan..." : "Start Scan"}
      </Button>
    </div>
  );
}
