import Link from 'next/link';
import { SignInButton, SignUpButton, SignedIn, SignedOut, UserButton } from '@clerk/nextjs';
import { Button } from '@/components/ui/button';
import { Shield, Zap, Lock, Target, Terminal, AlertTriangle } from 'lucide-react';

export default function HomePage() {
  return (
    <div className="min-h-screen bg-black">
      {/* Header */}
      <header className="border-b border-neutral-800">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-red-500" />
            <span className="text-xl font-bold">BREACH.AI</span>
          </div>

          <nav className="hidden md:flex items-center gap-8">
            <Link href="#features" className="text-sm text-neutral-400 hover:text-white transition">
              Features
            </Link>
            <Link href="/pricing" className="text-sm text-neutral-400 hover:text-white transition">
              Pricing
            </Link>
            <Link href="#" className="text-sm text-neutral-400 hover:text-white transition">
              Documentation
            </Link>
          </nav>

          <div className="flex items-center gap-4">
            <SignedOut>
              <SignInButton mode="modal">
                <Button variant="ghost" size="sm">
                  Sign In
                </Button>
              </SignInButton>
              <SignUpButton mode="modal">
                <Button size="sm">Get Started</Button>
              </SignUpButton>
            </SignedOut>
            <SignedIn>
              <Link href="/dashboard">
                <Button size="sm">Dashboard</Button>
              </Link>
              <UserButton afterSignOutUrl="/" />
            </SignedIn>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="py-24 md:py-32">
        <div className="container mx-auto px-6 text-center">
          <div className="inline-flex items-center gap-2 bg-red-500/10 text-red-500 px-4 py-2 rounded-full text-sm mb-6">
            <AlertTriangle className="h-4 w-4" />
            Enterprise Security Scanner
          </div>

          <h1 className="text-4xl md:text-6xl font-bold mb-6 max-w-4xl mx-auto leading-tight">
            Autonomous Penetration Testing{' '}
            <span className="text-red-500">Powered by AI</span>
          </h1>

          <p className="text-lg text-neutral-400 mb-8 max-w-2xl mx-auto">
            BREACH.AI autonomously discovers vulnerabilities, chains attack vectors, and provides
            actionable remediation - just like a human pentester, but faster.
          </p>

          <div className="flex items-center justify-center gap-4">
            <SignedOut>
              <SignUpButton mode="modal">
                <Button size="lg" className="gap-2">
                  <Terminal className="h-4 w-4" />
                  Start Free Trial
                </Button>
              </SignUpButton>
            </SignedOut>
            <SignedIn>
              <Link href="/dashboard">
                <Button size="lg" className="gap-2">
                  <Terminal className="h-4 w-4" />
                  Go to Dashboard
                </Button>
              </Link>
            </SignedIn>
            <Button variant="outline" size="lg">
              View Demo
            </Button>
          </div>

          {/* Terminal Preview */}
          <div className="mt-16 max-w-4xl mx-auto">
            <div className="bg-neutral-900 rounded-lg border border-neutral-800 overflow-hidden shadow-2xl">
              <div className="flex items-center gap-2 px-4 py-3 bg-neutral-800/50 border-b border-neutral-700">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <div className="w-3 h-3 rounded-full bg-yellow-500" />
                <div className="w-3 h-3 rounded-full bg-green-500" />
                <span className="ml-4 text-xs text-neutral-500 font-mono">breach scan</span>
              </div>
              <div className="p-6 font-mono text-sm text-left">
                <div className="text-neutral-500">$ breach scan https://target.com --deep</div>
                <div className="mt-4 text-green-400">[+] Initializing BREACH.AI Engine...</div>
                <div className="text-blue-400">[*] Running reconnaissance modules...</div>
                <div className="text-blue-400">[*] Discovered 47 endpoints</div>
                <div className="text-yellow-400">[!] Testing authentication bypass...</div>
                <div className="text-red-400">[CRITICAL] SQL Injection found in /api/users</div>
                <div className="text-red-400">[HIGH] XSS vulnerability in search parameter</div>
                <div className="text-green-400">[+] Scan complete: 2 critical, 3 high, 5 medium</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-24 bg-neutral-900/50">
        <div className="container mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Enterprise-Grade Security</h2>
            <p className="text-neutral-400 max-w-2xl mx-auto">
              30+ attack modules covering OWASP Top 10, authentication, injection, and more.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            <FeatureCard
              icon={<Zap className="h-8 w-8" />}
              title="AI-Powered Analysis"
              description="Intelligent vulnerability detection that understands context and chains attack vectors automatically."
            />
            <FeatureCard
              icon={<Target className="h-8 w-8" />}
              title="30+ Attack Modules"
              description="Comprehensive coverage including SQL injection, XSS, SSRF, authentication bypass, and more."
            />
            <FeatureCard
              icon={<Lock className="h-8 w-8" />}
              title="Continuous Monitoring"
              description="Schedule scans, track remediation, and get alerts when new vulnerabilities are discovered."
            />
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-neutral-800">
        <div className="container mx-auto px-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-6 w-6 text-red-500" />
              <span className="font-bold">BREACH.AI</span>
            </div>
            <p className="text-sm text-neutral-500">
              {new Date().getFullYear()} BREACH.AI. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

function FeatureCard({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="p-6 rounded-lg border border-neutral-800 bg-neutral-900/50">
      <div className="text-red-500 mb-4">{icon}</div>
      <h3 className="text-lg font-semibold mb-2">{title}</h3>
      <p className="text-neutral-400 text-sm">{description}</p>
    </div>
  );
}
