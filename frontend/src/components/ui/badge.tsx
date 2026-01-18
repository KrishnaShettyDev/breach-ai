import { cn, getSeverityBg, getSeverityColor } from "@/lib/utils";

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: "default" | "severity";
  severity?: string;
}

export function Badge({ className, variant = "default", severity, children, ...props }: BadgeProps) {
  if (variant === "severity" && severity) {
    return (
      <span
        className={cn(
          "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium",
          getSeverityBg(severity),
          getSeverityColor(severity),
          className
        )}
        {...props}
      >
        {children || severity.toUpperCase()}
      </span>
    );
  }

  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-[#f5f5f5] text-[#525252]",
        className
      )}
      {...props}
    >
      {children}
    </span>
  );
}
