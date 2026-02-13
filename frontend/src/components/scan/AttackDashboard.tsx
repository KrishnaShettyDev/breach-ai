"use client";

import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  AlertCircle, AlertTriangle, Info, CheckCircle2,
  Globe, Database, Shield, Bug, Loader2, ArrowRight
} from "lucide-react";

interface Finding {
  id: string;
  title: string;
  severity: string;
  category: string;
  endpoint: string;
  discovered_at?: string;
}

interface AttackDashboardProps {
  targetUrl: string;
  progress: number;
  currentPhase: string;
  findings: Finding[];
  isRunning: boolean;
  endpointsTested?: number;
  totalEndpoints?: number;
}

const PHASES = [
  { id: "recon", name: "Discovery", icon: Globe },
  { id: "injection", name: "Testing", icon: Bug },
  { id: "auth", name: "Auth", icon: Shield },
  { id: "idor", name: "Access", icon: Database },
];

export default function AttackDashboard({
  targetUrl,
  progress,
  currentPhase,
  findings,
  isRunning,
}: AttackDashboardProps) {
  // Count severities
  const critical = findings.filter(f => f.severity.toLowerCase() === "critical").length;
  const high = findings.filter(f => f.severity.toLowerCase() === "high").length;
  const medium = findings.filter(f => f.severity.toLowerCase() === "medium").length;
  const low = findings.filter(f => f.severity.toLowerCase() === "low").length;

  // Get current phase index
  const phaseIndex = PHASES.findIndex(p =>
    currentPhase?.toLowerCase().includes(p.id) ||
    (p.id === "injection" && currentPhase?.toLowerCase().includes("testing"))
  );

  return (
    <div className="space-y-4">
      {/* Progress Section */}
      <Card className="border border-[#e5e5e5]">
        <CardContent className="p-6">
          {/* Status Header */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              {isRunning ? (
                <div className="flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin text-blue-600" />
                  <span className="text-sm font-medium">Scanning</span>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-green-600" />
                  <span className="text-sm font-medium">Complete</span>
                </div>
              )}
              <span className="text-sm text-[#737373]">{targetUrl}</span>
            </div>
            <span className="text-2xl font-semibold">{progress}%</span>
          </div>

          {/* Progress Bar */}
          <div className="h-1.5 bg-[#f5f5f5] rounded-full overflow-hidden mb-6">
            <div
              className="h-full bg-black rounded-full transition-all duration-500 ease-out"
              style={{ width: `${progress}%` }}
            />
          </div>

          {/* Phase Steps */}
          <div className="flex items-center justify-between">
            {PHASES.map((phase, idx) => {
              const Icon = phase.icon;
              const isActive = idx === phaseIndex;
              const isPast = idx < phaseIndex || progress === 100;

              return (
                <div key={phase.id} className="flex items-center">
                  <div className="flex flex-col items-center">
                    <div className={`
                      w-10 h-10 rounded-full flex items-center justify-center transition-all
                      ${isPast ? "bg-black text-white" :
                        isActive ? "bg-black text-white ring-4 ring-black/10" :
                        "bg-[#f5f5f5] text-[#a3a3a3]"}
                    `}>
                      {isPast && !isActive ? (
                        <CheckCircle2 className="w-5 h-5" />
                      ) : (
                        <Icon className="w-5 h-5" />
                      )}
                    </div>
                    <span className={`text-xs mt-2 ${isPast || isActive ? "text-black font-medium" : "text-[#a3a3a3]"}`}>
                      {phase.name}
                    </span>
                  </div>
                  {idx < PHASES.length - 1 && (
                    <div className={`w-16 h-px mx-2 ${idx < phaseIndex ? "bg-black" : "bg-[#e5e5e5]"}`} />
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-3">
        <Card className={`border ${critical > 0 ? "border-red-200 bg-red-50" : "border-[#e5e5e5]"}`}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-[#737373] uppercase tracking-wide">Critical</p>
                <p className={`text-2xl font-semibold mt-1 ${critical > 0 ? "text-red-600" : "text-[#a3a3a3]"}`}>
                  {critical}
                </p>
              </div>
              <AlertCircle className={`w-5 h-5 ${critical > 0 ? "text-red-500" : "text-[#d4d4d4]"}`} />
            </div>
          </CardContent>
        </Card>

        <Card className={`border ${high > 0 ? "border-orange-200 bg-orange-50" : "border-[#e5e5e5]"}`}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-[#737373] uppercase tracking-wide">High</p>
                <p className={`text-2xl font-semibold mt-1 ${high > 0 ? "text-orange-600" : "text-[#a3a3a3]"}`}>
                  {high}
                </p>
              </div>
              <AlertTriangle className={`w-5 h-5 ${high > 0 ? "text-orange-500" : "text-[#d4d4d4]"}`} />
            </div>
          </CardContent>
        </Card>

        <Card className={`border ${medium > 0 ? "border-yellow-200 bg-yellow-50" : "border-[#e5e5e5]"}`}>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-[#737373] uppercase tracking-wide">Medium</p>
                <p className={`text-2xl font-semibold mt-1 ${medium > 0 ? "text-yellow-600" : "text-[#a3a3a3]"}`}>
                  {medium}
                </p>
              </div>
              <Info className={`w-5 h-5 ${medium > 0 ? "text-yellow-500" : "text-[#d4d4d4]"}`} />
            </div>
          </CardContent>
        </Card>

        <Card className="border border-[#e5e5e5]">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-[#737373] uppercase tracking-wide">Low</p>
                <p className={`text-2xl font-semibold mt-1 ${low > 0 ? "text-blue-600" : "text-[#a3a3a3]"}`}>
                  {low}
                </p>
              </div>
              <Info className={`w-5 h-5 ${low > 0 ? "text-blue-500" : "text-[#d4d4d4]"}`} />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
