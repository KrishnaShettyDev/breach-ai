"use client";

import { useState } from "react";
import { useAuth, useUser } from "@clerk/nextjs";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Copy, Plus, Trash2, CheckCircle, Eye, EyeOff } from "lucide-react";

interface APIKey {
  id: string;
  name: string;
  key_prefix: string;
  created_at: string;
  last_used_at: string | null;
}

export default function SettingsPage() {
  const { user } = useUser();
  const { getToken } = useAuth();
  const [apiKeys, setApiKeys] = useState<APIKey[]>([]);
  const [showNewKey, setShowNewKey] = useState(false);
  const [newKeyName, setNewKeyName] = useState("");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [showKey, setShowKey] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);

  const handleCreateKey = async () => {
    if (!newKeyName) return;

    try {
      const token = await getToken();
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/v1/auth/api-keys`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ name: newKeyName }),
        }
      );

      if (!response.ok) throw new Error("Failed to create API key");

      const data = await response.json();
      setCreatedKey(data.key);
      setApiKeys([
        ...apiKeys,
        {
          id: data.id,
          name: data.name,
          key_prefix: data.key_prefix,
          created_at: data.created_at,
          last_used_at: null,
        },
      ]);
      setNewKeyName("");
    } catch (error) {
      console.error("Failed to create API key:", error);
    }
  };

  const handleDeleteKey = async (keyId: string) => {
    if (!confirm("Delete this API key? This cannot be undone.")) return;

    try {
      const token = await getToken();
      await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/v1/auth/api-keys/${keyId}`,
        {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      setApiKeys(apiKeys.filter((k) => k.id !== keyId));
      setSuccess("API key deleted");
      setTimeout(() => setSuccess(null), 2000);
    } catch (error) {
      console.error("Failed to delete API key:", error);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSuccess("Copied to clipboard");
    setTimeout(() => setSuccess(null), 2000);
  };

  return (
    <div className="space-y-6 max-w-2xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="text-[#737373] mt-1">Manage your account and API access</p>
      </div>

      {success && (
        <div className="flex items-center gap-2 p-3 bg-green-50 border border-green-200 rounded-lg text-green-700 text-sm">
          <CheckCircle className="w-4 h-4" />
          {success}
        </div>
      )}

      {/* Profile */}
      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>Your account information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-sm font-medium">Email</label>
            <p className="text-[#737373] mt-1">{user?.primaryEmailAddress?.emailAddress}</p>
          </div>
          <div>
            <label className="text-sm font-medium">Name</label>
            <p className="text-[#737373] mt-1">{user?.fullName || "Not set"}</p>
          </div>
        </CardContent>
      </Card>

      {/* API Keys */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>API Keys</CardTitle>
              <CardDescription>Manage API keys for programmatic access</CardDescription>
            </div>
            {!showNewKey && !createdKey && (
              <Button size="sm" onClick={() => setShowNewKey(true)}>
                <Plus className="w-4 h-4 mr-2" />
                New Key
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* New Key Form */}
          {showNewKey && (
            <div className="p-4 border border-[#e5e5e5] rounded-lg space-y-3">
              <Input
                placeholder="Key name (e.g., CI/CD Pipeline)"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
              />
              <div className="flex gap-2">
                <Button onClick={handleCreateKey}>Create Key</Button>
                <Button variant="outline" onClick={() => setShowNewKey(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          )}

          {/* Created Key Display */}
          {createdKey && (
            <div className="p-4 bg-green-50 border border-green-200 rounded-lg space-y-3">
              <p className="text-sm font-medium text-green-800">
                API key created! Copy it now - you won&apos;t see it again.
              </p>
              <div className="flex items-center gap-2 bg-white p-2 rounded border">
                <code className="text-sm flex-1 font-mono">
                  {showKey ? createdKey : "•".repeat(40)}
                </code>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowKey(!showKey)}
                >
                  {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => copyToClipboard(createdKey)}
                >
                  <Copy className="w-4 h-4" />
                </Button>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setCreatedKey(null);
                  setShowNewKey(false);
                }}
              >
                Done
              </Button>
            </div>
          )}

          {/* Keys List */}
          {apiKeys.length === 0 && !showNewKey && !createdKey ? (
            <p className="text-sm text-[#737373] text-center py-4">
              No API keys yet
            </p>
          ) : (
            <div className="space-y-2">
              {apiKeys.map((key) => (
                <div
                  key={key.id}
                  className="flex items-center justify-between p-3 border border-[#e5e5e5] rounded-lg"
                >
                  <div>
                    <div className="font-medium text-sm">{key.name}</div>
                    <div className="text-xs text-[#737373] mt-1">
                      {key.key_prefix}... · Created {new Date(key.created_at).toLocaleDateString()}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleDeleteKey(key.id)}
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Usage */}
      <Card>
        <CardHeader>
          <CardTitle>Usage</CardTitle>
          <CardDescription>Your current plan and usage</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium">Free Plan</div>
              <div className="text-sm text-[#737373] mt-1">5 scans per month</div>
            </div>
            <Badge>Current Plan</Badge>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
