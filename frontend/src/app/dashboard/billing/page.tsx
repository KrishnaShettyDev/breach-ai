'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@clerk/nextjs';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { api, Subscription } from '@/lib/api';
import { cn } from '@/lib/utils';
import { Check, Loader2, CreditCard, Zap, Building2, Rocket } from 'lucide-react';

const plans = [
  {
    id: 'free',
    name: 'Free',
    price: '$0',
    description: 'For individual developers',
    icon: Zap,
    features: ['5 scans per month', '1 target', 'Basic vulnerability detection', 'Community support'],
  },
  {
    id: 'starter',
    name: 'Starter',
    price: '$49',
    priceId: 'price_starter',
    description: 'For small teams',
    icon: Rocket,
    popular: true,
    features: [
      '100 scans per month',
      '10 targets',
      'All attack modules',
      'API access',
      'Email support',
    ],
  },
  {
    id: 'business',
    name: 'Business',
    price: '$199',
    priceId: 'price_business',
    description: 'For growing companies',
    icon: Building2,
    features: [
      'Unlimited scans',
      'Unlimited targets',
      'Deep scan mode',
      'CI/CD integration',
      'Priority support',
      'Custom reports',
    ],
  },
];

export default function BillingPage() {
  const { getToken } = useAuth();
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [loading, setLoading] = useState(true);
  const [upgrading, setUpgrading] = useState<string | null>(null);

  useEffect(() => {
    loadSubscription();
  }, []);

  async function loadSubscription() {
    try {
      const token = await getToken();
      if (!token) return;
      const data = await api.getSubscription(token);
      setSubscription(data);
    } catch (err) {
      console.error('Failed to load subscription:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleUpgrade(priceId: string) {
    setUpgrading(priceId);
    try {
      const token = await getToken();
      if (!token) return;
      const { url } = await api.createCheckout(token, priceId);
      window.location.href = url;
    } catch (err) {
      console.error('Failed to create checkout:', err);
      setUpgrading(null);
    }
  }

  async function handleManage() {
    try {
      const token = await getToken();
      if (!token) return;
      const { url } = await api.createPortal(token);
      window.location.href = url;
    } catch (err) {
      console.error('Failed to open portal:', err);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-neutral-400" />
      </div>
    );
  }

  const currentPlan = subscription?.tier || 'free';

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Billing</h1>
        <p className="text-neutral-400 mt-1">Manage your subscription and billing</p>
      </div>

      {/* Current Plan */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CreditCard className="h-5 w-5" />
            Current Plan
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-bold capitalize">{currentPlan}</span>
                <Badge variant={currentPlan === 'free' ? 'secondary' : 'default'}>
                  {subscription?.status || 'active'}
                </Badge>
              </div>
              {subscription?.current_period_end && (
                <p className="text-sm text-neutral-400 mt-1">
                  Renews on {new Date(subscription.current_period_end).toLocaleDateString()}
                </p>
              )}
            </div>
            {currentPlan !== 'free' && (
              <Button variant="outline" onClick={handleManage}>
                Manage Subscription
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Plans */}
      <div>
        <h2 className="text-xl font-semibold mb-4">Available Plans</h2>
        <div className="grid md:grid-cols-3 gap-6">
          {plans.map((plan) => {
            const isCurrent = currentPlan === plan.id;
            const Icon = plan.icon;

            return (
              <Card
                key={plan.id}
                className={cn(
                  'relative',
                  plan.popular && 'border-red-500',
                  isCurrent && 'bg-neutral-900/50'
                )}
              >
                {plan.popular && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                    <Badge className="bg-red-500">Most Popular</Badge>
                  </div>
                )}
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <div className="p-2 rounded bg-neutral-800">
                      <Icon className="h-5 w-5 text-neutral-400" />
                    </div>
                    <CardTitle>{plan.name}</CardTitle>
                  </div>
                  <CardDescription>{plan.description}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <span className="text-4xl font-bold">{plan.price}</span>
                    <span className="text-neutral-400">/month</span>
                  </div>

                  <ul className="space-y-3">
                    {plan.features.map((feature) => (
                      <li key={feature} className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-green-500" />
                        {feature}
                      </li>
                    ))}
                  </ul>

                  {isCurrent ? (
                    <Button className="w-full" variant="secondary" disabled>
                      Current Plan
                    </Button>
                  ) : plan.priceId ? (
                    <Button
                      className="w-full"
                      variant={plan.popular ? 'default' : 'outline'}
                      onClick={() => handleUpgrade(plan.priceId!)}
                      disabled={upgrading === plan.priceId}
                    >
                      {upgrading === plan.priceId ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        'Upgrade'
                      )}
                    </Button>
                  ) : (
                    <Button className="w-full" variant="outline" disabled>
                      Free Forever
                    </Button>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>
    </div>
  );
}
