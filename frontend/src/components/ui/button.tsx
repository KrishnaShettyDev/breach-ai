import { cn } from "@/lib/utils";
import { forwardRef } from "react";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "outline" | "ghost";
  size?: "default" | "sm" | "lg";
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-black focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed",
          {
            "bg-black text-white hover:bg-black/90": variant === "default",
            "border border-black bg-white text-black hover:bg-[#f5f5f5]": variant === "outline",
            "text-black hover:bg-[#f5f5f5]": variant === "ghost",
          },
          {
            "h-10 px-4 rounded-lg text-sm": size === "default",
            "h-8 px-3 rounded-md text-xs": size === "sm",
            "h-12 px-6 rounded-lg text-base": size === "lg",
          },
          className
        )}
        {...props}
      />
    );
  }
);

Button.displayName = "Button";
