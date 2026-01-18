import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | Date | null): string {
  if (!date) return "—";
  return new Date(date).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

export function formatDuration(seconds: number | null): string {
  if (!seconds) return "—";
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
}

export function getSeverityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "severity-critical";
    case "high":
      return "severity-high";
    case "medium":
      return "severity-medium";
    case "low":
      return "severity-low";
    default:
      return "severity-info";
  }
}

export function getSeverityBg(severity: string): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "bg-severity-critical";
    case "high":
      return "bg-severity-high";
    case "medium":
      return "bg-severity-medium";
    case "low":
      return "bg-severity-low";
    default:
      return "bg-severity-info";
  }
}
