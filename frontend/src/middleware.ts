import { clerkMiddleware } from "@clerk/nextjs/server";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// In development, skip Clerk verification for speed
const isDev = process.env.NODE_ENV === "development";

export default clerkMiddleware(async (auth, req: NextRequest) => {
  // Fast path in development - trust the session
  if (isDev) {
    return NextResponse.next();
  }

  // In production, protect dashboard routes
  if (req.nextUrl.pathname.startsWith("/dashboard")) {
    await auth.protect();
  }

  return NextResponse.next();
});

export const config = {
  matcher: ["/dashboard/:path*"],
};
