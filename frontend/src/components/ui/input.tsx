import { cn } from "@/lib/utils";
import { forwardRef } from "react";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, ...props }, ref) => {
    return (
      <input
        ref={ref}
        className={cn(
          "w-full h-10 px-3 border border-[#e5e5e5] rounded-lg text-sm",
          "focus:outline-none focus:ring-2 focus:ring-black focus:border-transparent",
          "placeholder:text-[#a3a3a3]",
          className
        )}
        {...props}
      />
    );
  }
);

Input.displayName = "Input";
