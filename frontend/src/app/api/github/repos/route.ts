import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";

// Lists the signed-in user's GitHub repositories using their session token.
// Keeps the OAuth token server-side (never exposed to the browser).
export async function GET() {
  const session = await getServerSession(authOptions);
  const token = (session as any)?.accessToken;
  if (!token) {
    return NextResponse.json({ error: "Not signed in with GitHub" }, { status: 401 });
  }

  const res = await fetch(
    "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",
    { headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" } }
  );
  if (!res.ok) {
    return NextResponse.json(
      { error: `GitHub API error (${res.status}). Re-authorize if you recently changed scopes.` },
      { status: res.status }
    );
  }

  const repos = await res.json();
  return NextResponse.json(
    (Array.isArray(repos) ? repos : []).map((r: any) => ({
      full_name: r.full_name,
      html_url: r.html_url,
      private: r.private,
      updated_at: r.updated_at,
    }))
  );
}
