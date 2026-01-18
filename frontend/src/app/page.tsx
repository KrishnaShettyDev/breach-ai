import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Shield, Zap, Target, FileText } from "lucide-react";

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-white">
      {/* Nav */}
      <nav className="border-b border-[#e5e5e5]">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="text-xl font-semibold">
            BREACH
          </Link>
          <div className="flex items-center gap-4">
            <Link href="/sign-in">
              <Button variant="ghost">Sign In</Button>
            </Link>
            <Link href="/sign-up">
              <Button>Get Started</Button>
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="py-24 px-6">
        <div className="max-w-3xl mx-auto text-center">
          <h1 className="text-5xl md:text-6xl font-semibold tracking-tight mb-6">
            Security testing,
            <br />
            automated.
          </h1>
          <p className="text-xl text-[#737373] mb-10 max-w-xl mx-auto">
            Find vulnerabilities before attackers do. Autonomous penetration testing for modern applications.
          </p>
          <div className="flex items-center justify-center gap-4">
            <Link href="/sign-up">
              <Button size="lg">Start Free Trial</Button>
            </Link>
            <Link href="/sign-in">
              <Button variant="outline" size="lg">View Demo</Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="py-20 px-6 border-t border-[#e5e5e5]">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-semibold text-center mb-12">
            How it works
          </h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Card className="p-6">
              <Target className="w-8 h-8 mb-4" strokeWidth={1.5} />
              <h3 className="font-semibold mb-2">Add Target</h3>
              <p className="text-sm text-[#737373]">
                Add your application URL and verify ownership
              </p>
            </Card>
            <Card className="p-6">
              <Zap className="w-8 h-8 mb-4" strokeWidth={1.5} />
              <h3 className="font-semibold mb-2">Run Scan</h3>
              <p className="text-sm text-[#737373]">
                Our engine tests 88+ attack vectors automatically
              </p>
            </Card>
            <Card className="p-6">
              <Shield className="w-8 h-8 mb-4" strokeWidth={1.5} />
              <h3 className="font-semibold mb-2">Find Issues</h3>
              <p className="text-sm text-[#737373]">
                Get detailed findings with proof-of-concept
              </p>
            </Card>
            <Card className="p-6">
              <FileText className="w-8 h-8 mb-4" strokeWidth={1.5} />
              <h3 className="font-semibold mb-2">Get Report</h3>
              <p className="text-sm text-[#737373]">
                Export reports with remediation guidance
              </p>
            </Card>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section className="py-20 px-6 bg-black text-white">
        <div className="max-w-4xl mx-auto">
          <div className="grid grid-cols-3 gap-8 text-center">
            <div>
              <div className="text-4xl font-semibold mb-2">88+</div>
              <div className="text-[#a3a3a3]">Attack Modules</div>
            </div>
            <div>
              <div className="text-4xl font-semibold mb-2">OWASP</div>
              <div className="text-[#a3a3a3]">Top 10 Coverage</div>
            </div>
            <div>
              <div className="text-4xl font-semibold mb-2">Real</div>
              <div className="text-[#a3a3a3]">PoC Exploits</div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 px-6">
        <div className="max-w-2xl mx-auto text-center">
          <h2 className="text-3xl font-semibold mb-4">
            Ready to secure your application?
          </h2>
          <p className="text-[#737373] mb-8">
            Start finding vulnerabilities in minutes.
          </p>
          <Link href="/sign-up">
            <Button size="lg">Get Started Free</Button>
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[#e5e5e5] py-8 px-6">
        <div className="max-w-6xl mx-auto flex items-center justify-between text-sm text-[#737373]">
          <div>BREACH Security Platform</div>
          <div>Built for developers who ship fast</div>
        </div>
      </footer>
    </div>
  );
}
