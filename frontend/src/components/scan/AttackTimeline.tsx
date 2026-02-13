"use client";

import { useEffect, useRef } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertCircle, AlertTriangle, Info, Clock } from "lucide-react";

interface Finding {
  id: string;
  title: string;
  severity: string;
  category: string;
  discovered_at?: string;
}

interface AttackTimelineProps {
  findings: Finding[];
  isRunning: boolean;
  startedAt?: string;
  currentPhase?: string;
  progress?: number;
}

const SEVERITY_CONFIG = {
  critical: { color: "text-red-600", bg: "bg-red-50", border: "border-red-200", dot: "bg-red-500" },
  high: { color: "text-orange-600", bg: "bg-orange-50", border: "border-orange-200", dot: "bg-orange-500" },
  medium: { color: "text-yellow-600", bg: "bg-yellow-50", border: "border-yellow-200", dot: "bg-yellow-500" },
  low: { color: "text-blue-600", bg: "bg-blue-50", border: "border-blue-200", dot: "bg-blue-500" },
  info: { color: "text-gray-600", bg: "bg-gray-50", border: "border-gray-200", dot: "bg-gray-400" },
};

export default function AttackTimeline({ findings, isRunning }: AttackTimelineProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to latest
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [findings.length]);

  // Sort by discovered time (newest first for display, but we'll reverse for timeline)
  const sortedFindings = [...findings]
    .sort((a, b) => {
      if (!a.discovered_at || !b.discovered_at) return 0;
      return new Date(b.discovered_at).getTime() - new Date(a.discovered_at).getTime();
    })
    .slice(0, 20); // Show last 20

  if (findings.length === 0) {
    return (
      <Card className="border border-[#e5e5e5]">
        <CardContent className="p-6">
          <div className="flex items-center gap-2 mb-4">
            <Clock className="w-4 h-4 text-[#737373]" />
            <span className="text-sm font-medium">Activity</span>
            {isRunning && (
              <Badge variant="outline" className="ml-auto text-xs">
                Live
              </Badge>
            )}
          </div>
          <div className="text-center py-8 text-[#737373]">
            <p className="text-sm">No findings yet</p>
            {isRunning && <p className="text-xs mt-1">Scanning in progress...</p>}
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border border-[#e5e5e5]">
      <CardContent className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <Clock className="w-4 h-4 text-[#737373]" />
          <span className="text-sm font-medium">Recent Activity</span>
          <span className="text-xs text-[#a3a3a3]">{findings.length} findings</span>
          {isRunning && (
            <Badge variant="outline" className="ml-auto text-xs">
              <span className="w-1.5 h-1.5 bg-green-500 rounded-full mr-1.5 animate-pulse" />
              Live
            </Badge>
          )}
        </div>

        <div ref={scrollRef} className="space-y-3 max-h-[300px] overflow-y-auto pr-2">
          {sortedFindings.map((finding, idx) => {
            const severity = finding.severity.toLowerCase();
            const config = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.info;
            const isNew = idx === 0 && isRunning;

            return (
              <div
                key={finding.id}
                className={`
                  flex items-start gap-3 p-3 rounded-lg border transition-all
                  ${isNew ? `${config.border} ${config.bg}` : "border-transparent hover:bg-[#fafafa]"}
                `}
              >
                {/* Timeline dot */}
                <div className="flex flex-col items-center pt-1">
                  <div className={`w-2 h-2 rounded-full ${config.dot}`} />
                  {idx < sortedFindings.length - 1 && (
                    <div className="w-px h-full bg-[#e5e5e5] mt-1" />
                  )}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-medium uppercase ${config.color}`}>
                      {finding.severity}
                    </span>
                    <span className="text-xs text-[#a3a3a3]">·</span>
                    <span className="text-xs text-[#737373]">{finding.category}</span>
                    {isNew && (
                      <Badge className="ml-auto bg-black text-white text-[10px] px-1.5 py-0">
                        New
                      </Badge>
                    )}
                  </div>
                  <p className="text-sm text-black mt-1 truncate">{finding.title}</p>
                  {finding.discovered_at && (
                    <p className="text-xs text-[#a3a3a3] mt-1">
                      {new Date(finding.discovered_at).toLocaleTimeString()}
                    </p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
