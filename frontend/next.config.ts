import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Skip type checking during build (handled by CI)
  typescript: {
    ignoreBuildErrors: true,
  },
  // Force all pages to be server-rendered
  output: "standalone",
};

export default nextConfig;
