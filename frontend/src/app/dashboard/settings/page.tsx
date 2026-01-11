'use client';

import { useUser, useOrganization } from '@clerk/nextjs';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { User, Building2, Shield, Bell, ExternalLink } from 'lucide-react';

export default function SettingsPage() {
  const { user } = useUser();
  const { organization } = useOrganization();

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-neutral-400 mt-1">Manage your account and organization settings</p>
      </div>

      {/* Profile */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            Profile
          </CardTitle>
          <CardDescription>Your personal account information</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-6">
            {user?.imageUrl ? (
              <img
                src={user.imageUrl}
                alt={user.fullName || 'Profile'}
                className="h-16 w-16 rounded-full"
              />
            ) : (
              <div className="h-16 w-16 rounded-full bg-neutral-800 flex items-center justify-center">
                <User className="h-8 w-8 text-neutral-400" />
              </div>
            )}
            <div>
              <h3 className="font-semibold text-lg">{user?.fullName || 'User'}</h3>
              <p className="text-neutral-400">{user?.primaryEmailAddress?.emailAddress}</p>
            </div>
          </div>
          <div className="mt-6">
            <Button variant="outline" asChild>
              <a href="https://accounts.clerk.com/user" target="_blank" rel="noopener noreferrer">
                Manage Profile
                <ExternalLink className="h-4 w-4 ml-2" />
              </a>
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Organization */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Building2 className="h-5 w-5" />
            Organization
          </CardTitle>
          <CardDescription>Your organization settings</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 rounded-lg border border-neutral-800">
              <div className="flex items-center gap-4">
                {organization?.imageUrl ? (
                  <img
                    src={organization.imageUrl}
                    alt={organization.name}
                    className="h-12 w-12 rounded"
                  />
                ) : (
                  <div className="h-12 w-12 rounded bg-neutral-800 flex items-center justify-center">
                    <Building2 className="h-6 w-6 text-neutral-400" />
                  </div>
                )}
                <div>
                  <h3 className="font-semibold">{organization?.name || "Personal Workspace"}</h3>
                  <p className="text-sm text-neutral-400">
                    {organization ? `${organization.membersCount || 1} member(s)` : 'Just you'}
                  </p>
                </div>
              </div>
              <Badge variant="secondary">Owner</Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Security */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Security
          </CardTitle>
          <CardDescription>Security settings and authentication</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 rounded-lg border border-neutral-800">
              <div>
                <h3 className="font-medium">Two-Factor Authentication</h3>
                <p className="text-sm text-neutral-400">
                  Add an extra layer of security to your account
                </p>
              </div>
              <Button variant="outline" asChild>
                <a href="https://accounts.clerk.com/user/security" target="_blank">
                  Configure
                </a>
              </Button>
            </div>
            <div className="flex items-center justify-between p-4 rounded-lg border border-neutral-800">
              <div>
                <h3 className="font-medium">Active Sessions</h3>
                <p className="text-sm text-neutral-400">Manage your active login sessions</p>
              </div>
              <Button variant="outline" asChild>
                <a href="https://accounts.clerk.com/user/security" target="_blank">
                  View Sessions
                </a>
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Notifications */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            Notifications
          </CardTitle>
          <CardDescription>Configure how you receive notifications</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 rounded-lg border border-neutral-800">
              <div>
                <h3 className="font-medium">Email Notifications</h3>
                <p className="text-sm text-neutral-400">
                  Receive scan completion and critical finding alerts
                </p>
              </div>
              <Badge>Enabled</Badge>
            </div>
            <div className="flex items-center justify-between p-4 rounded-lg border border-neutral-800">
              <div>
                <h3 className="font-medium">Slack Integration</h3>
                <p className="text-sm text-neutral-400">
                  Send notifications to your Slack workspace
                </p>
              </div>
              <Button variant="outline" size="sm">
                Configure
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
