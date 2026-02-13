"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { useRouter, useSearchParams } from "next/navigation";
import { mutate } from "swr";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useTargets } from "@/hooks/use-api";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Check, Plus, AlertCircle } from "lucide-react";

// Single GOD LEVEL scan mode - does EVERYTHING
const scanMode = {
  id: "deep",
  name: "GOD LEVEL Deep Scan",
  description: "Comprehensive security assessment. Crawls entire site, tests all injection types (SQLi, XSS, SSRF, CMDi, LFI), authentication bypass, IDOR, and more. Returns REAL vulnerabilities with proof.",
  time: "~15-20 min",
};

export default function NewScanPage() {
  const { getToken } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const preselectedTarget = searchParams.get("target");

  const { data: targets, isLoading: loading } = useTargets();
  const [selectedTarget, setSelectedTarget] = useState<string | null>(preselectedTarget);
  const [selectedMode] = useState("deep"); // Only one mode - GOD LEVEL
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // New target form
  const [showNewTarget, setShowNewTarget] = useState(false);
  const [newTargetUrl, setNewTargetUrl] = useState("");

  const handleCreateTarget = async () => {
    if (!newTargetUrl) return;

    try {
      const token = await getToken();
      if (!token) return;

      const url = newTargetUrl.startsWith("http") ? newTargetUrl : `https://${newTargetUrl}`;
      const target = await api.createTarget(token, {
        url,
        name: new URL(url).hostname,
      });

      mutate("targets");
      setSelectedTarget(target.id);
      setShowNewTarget(false);
      setNewTargetUrl("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Failed to create target");
    }
  };

  const handleStartScan = async () => {
    if (!selectedTarget) {
      setError("Please select a target");
      return;
    }

    const target = targets?.find((t) => t.id === selectedTarget);
    if (!target) {
      setError("Target not found");
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const token = await getToken();
      if (!token) return;

      const scan = await api.createScan(token, {
        target_id: selectedTarget,
        target_url: target.url,
        mode: selectedMode,
      });

      mutate("scans-1");
      mutate("stats");
      router.push(`/dashboard/scans/${scan.id}`);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Failed to start scan");
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="max-w-2xl mx-auto space-y-6">
        <div>
          <Skeleton className="h-8 w-32" />
          <Skeleton className="h-4 w-48 mt-2" />
        </div>
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-32" />
          </CardHeader>
          <CardContent className="space-y-3">
            {[...Array(2)].map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">New Scan</h1>
        <p className="text-[#737373] mt-1">Start a security scan</p>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          <AlertCircle className="w-4 h-4" />
          {error}
          <button onClick={() => setError(null)} className="ml-auto">×</button>
        </div>
      )}

      {/* Target Selection */}
      <Card>
        <CardHeader>
          <CardTitle>Target</CardTitle>
          <CardDescription>Select a website to scan</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {targets?.map((target) => (
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
              {selectedTarget === target.id && <Check className="w-4 h-4" />}
            </button>
          ))}

          {!showNewTarget ? (
            <Button
              variant="outline"
              className="w-full"
              onClick={() => setShowNewTarget(true)}
            >
              <Plus className="w-4 h-4 mr-2" />
              Add Target
            </Button>
          ) : (
            <div className="space-y-3 p-4 border border-[#e5e5e5] rounded-lg">
              <Input
                placeholder="example.com"
                value={newTargetUrl}
                onChange={(e) => setNewTargetUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleCreateTarget()}
                autoFocus
              />
              <div className="flex gap-2">
                <Button onClick={handleCreateTarget}>Add</Button>
                <Button variant="outline" onClick={() => setShowNewTarget(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan Mode - Single GOD LEVEL Mode */}
      <Card>
        <CardHeader>
          <CardTitle>Scan Mode</CardTitle>
          <CardDescription>One mode. Everything. God level.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="w-full p-4 border-2 border-black bg-[#f5f5f5] rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-bold text-lg">{scanMode.name}</div>
                <div className="text-sm text-[#737373] mt-1">{scanMode.description}</div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium bg-black text-white px-2 py-1 rounded">{scanMode.time}</span>
                <Check className="w-5 h-5" />
              </div>
            </div>
            <div className="mt-3 pt-3 border-t border-[#e5e5e5]">
              <div className="text-xs text-[#737373] space-y-1">
                <div>• Full website crawl (500+ pages)</div>
                <div>• SQL Injection, XSS, SSRF, Command Injection, LFI</div>
                <div>• Authentication bypass & JWT attacks</div>
                <div>• IDOR & privilege escalation</div>
                <div>• Real proof with sample data & curl commands</div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Submit */}
      <Button
        size="lg"
        className="w-full"
        onClick={handleStartScan}
        disabled={submitting || !selectedTarget}
      >
        {submitting ? "Starting..." : "Start Scan"}
      </Button>
    </div>
  );
}
