import { withAuth } from "next-auth/middleware";
import { NextResponse } from "next/server";

// Auth-protected app routes. The landing page ("/"), NextAuth API routes, and
// static assets stay public; everything that shows or mutates user data sits
// behind login.
//
// GitHub OAuth is optional for self-hosted deployments — if no provider is
// configured (GITHUB_CLIENT_ID/SECRET unset) there is no way to sign in, so we
// disable enforcement to avoid locking the operator out. Set
// AUTH_ENFORCED=false to explicitly opt out as well.
const oauthConfigured = Boolean(
  process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET,
);
const enforced =
  process.env.AUTH_ENFORCED !== "false" && oauthConfigured;

export default withAuth(
  function middleware() {
    return NextResponse.next();
  },
  {
    callbacks: {
      // When enforcement is off, always authorize (no redirect loop). When on,
      // require a valid session token.
      authorized: ({ token }) => (enforced ? Boolean(token) : true),
    },
  },
);

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/scan/:path*",
    "/reports/:path*",
    "/settings/:path*",
  ],
};
