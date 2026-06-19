import type { NextAuthOptions } from "next-auth";
import GithubProvider from "next-auth/providers/github";

const providers = [];

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  providers.push(
    GithubProvider({
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      // Request scopes needed to list repos and open fix PRs. Without this the
      // token only has basic profile access and repo listing/PRs fail.
      authorization: {
        params: { scope: "read:user user:email repo" },
      },
    })
  );
}

export const authOptions: NextAuthOptions = {
  providers,
  callbacks: {
    async jwt({ token, account }) {
      if (account?.access_token) {
        token.accessToken = account.access_token;
        // Exchange the GitHub token for a VEXIS JWT so backend API calls are
        // authenticated and scans are owned by this user.
        try {
          // This runs server-side, so prefer an internal backend URL (e.g. the
          // Docker service name) and fall back to the public one.
          const base =
            process.env.BACKEND_INTERNAL_URL ??
            process.env.NEXT_PUBLIC_API_URL ??
            "http://localhost:8000";
          const res = await fetch(`${base}/api/v1/auth/token`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ access_token: account.access_token }),
          });
          if (res.ok) {
            const data = await res.json();
            token.vexisToken = data.access_token;
          }
        } catch {
          /* backend unreachable — fall back to anonymous backend access */
        }
      }
      return token;
    },
    async session({ session, token }) {
      (session as any).accessToken = token.accessToken;
      (session as any).vexisToken = token.vexisToken;
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET,
};
