import Link from 'next/link';
import { SignUpButton, SignedIn, SignedOut } from '@clerk/nextjs';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Shield, Check, Zap, Rocket, Building2, ArrowLeft } from 'lucide-react';

const plans = [
  {
    id: 'free',
    name: 'Free',
    price: '$0',
    description: 'For individual developers exploring security testing',
    icon: Zap,
    features: [
      '5 scans per month',
      '1 target',
      'Basic vulnerability detection',
      'OWASP Top 10 coverage',
      'Community support',
    ],
    cta: 'Get Started Free',
  },
  {
    id: 'starter',
    name: 'Starter',
    price: '$49',
    description: 'For small teams shipping secure software',
    icon: Rocket,
    popular: true,
    features: [
      '100 scans per month',
      '10 targets',
      'All 30+ attack modules',
      'API access',
      'CI/CD integration',
      'Email support',
      'PDF reports',
    ],
    cta: 'Start Free Trial',
  },
  {
    id: 'business',
    name: 'Business',
    price: '$199',
    description: 'For growing companies with security requirements',
    icon: Building2,
    features: [
      'Unlimited scans',
      'Unlimited targets',
      'Deep scan with AI attack chaining',
      'Scheduled scans',
      'Priority support',
      'Custom reports',
      'Team collaboration',
      'Compliance reporting',
    ],
    cta: 'Start Free Trial',
  },
];

export default function PricingPage() {
  return (
    <div className="min-h-screen bg-black">
      {/* Header */}
      <header className="border-b border-neutral-800">
        <div className="container mx-auto px-6 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-red-500" />
            <span className="text-xl font-bold">BREACH.AI</span>
          </Link>
          <Link href="/">
            <Button variant="ghost" size="sm" className="gap-2">
              <ArrowLeft className="h-4 w-4" />
              Back to Home
            </Button>
          </Link>
        </div>
      </header>

      {/* Pricing */}
      <section className="py-24">
        <div className="container mx-auto px-6">
          <div className="text-center mb-16">
            <h1 className="text-4xl md:text-5xl font-bold mb-4">
              Simple, Transparent Pricing
            </h1>
            <p className="text-lg text-neutral-400 max-w-2xl mx-auto">
              Choose the plan that fits your security needs. All plans include a 14-day free trial.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
            {plans.map((plan) => {
              const Icon = plan.icon;

              return (
                <Card
                  key={plan.id}
                  className={`relative ${plan.popular ? 'border-red-500' : ''}`}
                >
                  {plan.popular && (
                    <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                      <Badge className="bg-red-500">Most Popular</Badge>
                    </div>
                  )}
                  <CardHeader className="pb-4">
                    <div className="flex items-center gap-2 mb-2">
                      <div className="p-2 rounded bg-neutral-800">
                        <Icon className="h-5 w-5 text-neutral-400" />
                      </div>
                      <CardTitle>{plan.name}</CardTitle>
                    </div>
                    <CardDescription>{plan.description}</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div>
                      <span className="text-5xl font-bold">{plan.price}</span>
                      <span className="text-neutral-400">/month</span>
                    </div>

                    <ul className="space-y-3">
                      {plan.features.map((feature) => (
                        <li key={feature} className="flex items-center gap-2 text-sm">
                          <Check className="h-4 w-4 text-green-500 flex-shrink-0" />
                          {feature}
                        </li>
                      ))}
                    </ul>

                    <SignedOut>
                      <SignUpButton mode="modal">
                        <Button
                          className="w-full"
                          variant={plan.popular ? 'default' : 'outline'}
                        >
                          {plan.cta}
                        </Button>
                      </SignUpButton>
                    </SignedOut>
                    <SignedIn>
                      <Link href="/dashboard/billing">
                        <Button
                          className="w-full"
                          variant={plan.popular ? 'default' : 'outline'}
                        >
                          Go to Dashboard
                        </Button>
                      </Link>
                    </SignedIn>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* FAQ */}
          <div className="mt-24 max-w-3xl mx-auto">
            <h2 className="text-2xl font-bold text-center mb-8">Frequently Asked Questions</h2>
            <div className="space-y-6">
              <FaqItem
                question="Can I try BREACH.AI before committing?"
                answer="Yes! All paid plans include a 14-day free trial. No credit card required to start."
              />
              <FaqItem
                question="What happens when I exceed my scan limit?"
                answer="You'll receive a notification when approaching your limit. You can upgrade at any time to increase your quota."
              />
              <FaqItem
                question="Can I cancel my subscription?"
                answer="Absolutely. You can cancel anytime from your dashboard. You'll keep access until the end of your billing period."
              />
              <FaqItem
                question="Do you offer enterprise pricing?"
                answer="Yes! For large organizations with specific requirements, contact us for custom enterprise pricing."
              />
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

function FaqItem({ question, answer }: { question: string; answer: string }) {
  return (
    <div className="p-6 rounded-lg border border-neutral-800">
      <h3 className="font-semibold mb-2">{question}</h3>
      <p className="text-neutral-400 text-sm">{answer}</p>
    </div>
  );
}
