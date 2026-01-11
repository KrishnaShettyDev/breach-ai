'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { UserButton } from '@clerk/nextjs';
import { cn } from '@/lib/utils';
import {
  Shield,
  LayoutDashboard,
  Target,
  Scan,
  Settings,
  Key,
  CreditCard,
} from 'lucide-react';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Targets', href: '/dashboard/targets', icon: Target },
  { name: 'Scans', href: '/dashboard/scans', icon: Scan },
  { name: 'API Keys', href: '/dashboard/api-keys', icon: Key },
  { name: 'Billing', href: '/dashboard/billing', icon: CreditCard },
  { name: 'Settings', href: '/dashboard/settings', icon: Settings },
];

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();

  return (
    <div className="min-h-screen bg-black flex">
      {/* Sidebar */}
      <aside className="w-64 border-r border-neutral-800 flex flex-col">
        <div className="p-6 border-b border-neutral-800">
          <Link href="/dashboard" className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-red-500" />
            <span className="text-xl font-bold">BREACH.AI</span>
          </Link>
        </div>

        <nav className="flex-1 p-4">
          <ul className="space-y-1">
            {navigation.map((item) => {
              const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
              return (
                <li key={item.name}>
                  <Link
                    href={item.href}
                    className={cn(
                      'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors',
                      isActive
                        ? 'bg-red-500/10 text-red-500'
                        : 'text-neutral-400 hover:text-white hover:bg-neutral-800'
                    )}
                  >
                    <item.icon className="h-5 w-5" />
                    {item.name}
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="p-4 border-t border-neutral-800">
          <div className="flex items-center gap-3 px-3 py-2">
            <UserButton
              afterSignOutUrl="/"
              appearance={{
                elements: {
                  avatarBox: 'h-8 w-8',
                },
              }}
            />
            <span className="text-sm text-neutral-400">Account</span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <div className="p-8">{children}</div>
      </main>
    </div>
  );
}
